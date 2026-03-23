# kntrl Detection & Enforcement Techniques

This document describes all the techniques kntrl uses for runtime security monitoring, policy enforcement, and reporting.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [eBPF Kernel Instrumentation](#2-ebpf-kernel-instrumentation)
3. [Network Connection Monitoring](#3-network-connection-monitoring)
4. [DNS Monitoring & Caching](#4-dns-monitoring--caching)
5. [TLS SNI Extraction](#5-tls-sni-extraction)
6. [Process Lifecycle Tracking](#6-process-lifecycle-tracking)
7. [File Access Monitoring](#7-file-access-monitoring)
8. [Environment Variable Detection](#8-environment-variable-detection)
9. [Policy Engine (OPA/Rego)](#9-policy-engine-oparego)
10. [Egress Filtering & Blocking](#10-egress-filtering--blocking)
11. [Established Connection Preloading](#11-established-connection-preloading)
12. [Self-Filtering](#12-self-filtering)
13. [Live Policy Reload (SIGHUP)](#13-live-policy-reload-sighup)
14. [Reporting & Output](#14-reporting--output)
15. [Webhook Alerting](#15-webhook-alerting)
16. [Configuration System](#16-configuration-system)
17. [Detection Coverage Matrix](#17-detection-coverage-matrix)

---

## 1. Architecture Overview

kntrl is a runtime security agent that uses eBPF to observe kernel-level events and OPA (Open Policy Agent) for policy decisions. The architecture has three layers:

```
 Userspace                           Kernel
+--------------------------+        +-------------------------+
| CLI (cobra)              |        | eBPF Programs           |
| Config (YAML/CLI flags)  |        |  - Kprobes (6)          |
| OPA Policy Engine        |  <-->  |  - Tracepoints (4)      |
| Reporter (tables/JSON)   |        |  - CGroup SKB (1)       |
| Webhook Client           |        |                         |
| Process Tree             |        | eBPF Maps               |
| DNS Cache                |        |  - Ring Buffers (6)     |
+--------------------------+        |  - LRU Hash Maps (3)    |
                                    |  - Hash Maps (4)        |
                                    +-------------------------+
```

**Data flow**: BPF programs capture events at kernel level -> ring buffers deliver to userspace -> Go goroutines process, enrich, and evaluate policy -> results written to report and optional webhook.

---

## 2. eBPF Kernel Instrumentation

### BPF Programs

kntrl loads **11 eBPF programs** across 4 program types:

| Program | Type | Attachment Point | Purpose |
|---------|------|------------------|---------|
| `kprobe__tcp_v4_connect` | Kprobe | `tcp_v4_connect` | IPv4 TCP connection attempts |
| `kprobe__ip4_datagram_connect` | Kprobe | `ip4_datagram_connect` | IPv4 UDP connections |
| `kprobe__tcp_v6_connect` | Kprobe | `tcp_v6_connect` | IPv6 TCP connection attempts |
| `kprobe__udpv6_sendmsg` | Kprobe | `udpv6_sendmsg` | IPv6 UDP sends |
| `kprobe__skb_consume_udp` | Kprobe | `skb_consume_udp` | DNS packet capture (port 53) |
| `kprobe__security_socket_create` | Kprobe | `security_socket_create` | Raw socket creation detection |
| `inet_sock_set_state` | Tracepoint | `sock:inet_sock_set_state` | TCP state transitions |
| `trace_exec` | Tracepoint | `sched:sched_process_exec` | Process execution (execve) |
| `trace_fork` | Tracepoint | `sched:sched_process_fork` | Process forking |
| `trace_openat` | Tracepoint | `syscalls:sys_enter_openat` | File open operations |
| `egress` | CGroup SKB | `/sys/fs/cgroup` (inet egress) | Packet-level egress filtering |

### BPF Maps

| Map | Type | Key | Value | Size | Purpose |
|-----|------|-----|-------|------|---------|
| `allowed_ip_map` | LRU_HASH | `u32` (IPv4) | `u32` (1) | 1024 | IPv4 allowlist |
| `allowed_ipv6_map` | LRU_HASH | `u8[16]` (IPv6) | `u32` (1) | 1024 | IPv6 allowlist |
| `allowed_hosts_map` | LRU_HASH | `char[256]` | `u32` (1) | 1024 | Domain allowlist |
| `allowed_dns_servers_map` | HASH | `u32` (IPv4) | `u32` (1) | 64 | Permitted DNS servers |
| `mode_map` | HASH | `u32` (0) | `u32` (0/1) | 1 | Monitor vs Trace mode |
| `process_monitor_map` | HASH | `u32` (0) | `u32` (1) | 1 | Process monitoring toggle |
| `file_monitor_map` | HASH | `u32` (0) | `u32` (1) | 1 | File monitoring toggle |
| `self_tgid_map` | HASH | `u32` (0) | `u32` (TGID) | 1 | kntrl's own PID for self-filtering |
| `ipv4_events` | RINGBUF | - | - | 256KB | IPv4 event delivery |
| `ipv6_events` | RINGBUF | - | - | 256KB | IPv6 event delivery |
| `dns_events` | RINGBUF | - | - | 128KB | DNS event delivery |
| `process_events` | RINGBUF | - | - | 128KB | Process event delivery |
| `file_events` | RINGBUF | - | - | 128KB | File event delivery |
| `sni_events` | RINGBUF | - | - | 64KB | TLS SNI event delivery |

### CO-RE (Compile Once Run Everywhere)

BPF programs use `BPF_CORE_READ()` macros and `vmlinux.h` for portability across kernel versions. Compiled via bpf2go and embedded in the Go binary at build time.

---

## 3. Network Connection Monitoring

### IPv4 Connections

**Hook points**: `kprobe__tcp_v4_connect` (TCP), `kprobe__ip4_datagram_connect` (UDP)

When a process initiates an outbound connection:

1. BPF kprobe fires, captures: PID, process name, destination IP/port, protocol
2. Event sent to userspace via `ipv4_events` ring buffer
3. Userspace enrichment:
   - Resolves process name from `/proc/[pid]/exe` (BPF `comm` field is spoofable via `prctl`)
   - Performs reverse DNS lookup with caching (150ms timeout)
   - Collects process ancestry from in-memory process tree
4. Policy evaluation via OPA (in trace mode)
5. Result: **pass** (IP added to kernel allowlist) or **block**

### IPv6 Connections

**Hook points**: `kprobe__tcp_v6_connect` (TCP), `kprobe__udpv6_sendmsg` (UDP)

Same pipeline as IPv4, with 128-bit address handling. Separate `allowed_ipv6_map` in kernel.

### Event Structure

```c
struct ipv4_event_t {
    u64 ts_us;        // Timestamp (microseconds)
    u32 pid;          // Process ID
    u16 af;           // Address family
    char task[16];    // Process name
    u8  proto;        // IPPROTO_TCP (6) or IPPROTO_UDP (17)
    u32 daddr;        // Destination IPv4 (little-endian)
    u16 dport;        // Destination port
};
```

### Port 53 Filtering

DNS traffic (port 53) is skipped in the network event loop since it's captured separately by the DNS monitor, avoiding duplicate reporting.

---

## 4. DNS Monitoring & Caching

### Kernel-Level DNS Capture

**Hook point**: `kprobe__skb_consume_udp`

The BPF program intercepts UDP packets on port 53 and parses DNS wire format:

- **Queries**: Captures all outbound DNS queries (domain name, query type)
- **Responses**: Parses A/AAAA records, validates against `allowed_hosts_map` and `allowed_dns_servers_map`
- Event structure includes: PID, DNS server IP, query domain (256 bytes), query type, query/response flag

### Userspace DNS Processing

1. **Noise filtering**: Skips reverse DNS (`in-addr.arpa`, `ip6.arpa`), internal domains (`*.internal`), and empty queries
2. **Deduplication**: Per-domain per-direction (query vs response) with 2-second TTL window
3. **Forward cache population**: DNS responses trigger async domain-to-IP cache entries

### Dual-Layer DNS Cache

```
Forward Cache (from observed DNS responses)
  fwdDNSCache[IP] -> []domains
  TTL: 5 minutes
  Populated: when BPF captures DNS responses

Reverse Cache (from system lookups)
  dnsCache[IP] -> {domains, error, expiry}
  TTL: 5 minutes (success), 30 seconds (failure)
  Populated: on-demand reverse lookups
```

**Lookup priority**: Forward cache (observed DNS) > Reverse cache > Live `LookupAddr()` (150ms timeout)

### Async DNS Worker

A background goroutine processes DNS cache population requests via a 256-entry buffered channel. Non-blocking: drops requests if the channel is full to avoid slowing the hot path.

---

## 5. TLS SNI Extraction

**Hook point**: CGroup SKB egress filter (`egress` program)

kntrl performs **in-kernel TLS ClientHello parsing** to extract the Server Name Indication (SNI) hostname from outbound HTTPS connections.

### Parsing Stack

```
IP Header (ihl*4 bytes)
 -> TCP Header (doff*4 bytes)
     -> TLS Record (content_type == 0x16 = Handshake)
         -> Handshake Message (type == 0x01 = ClientHello)
             -> Skip: version(2) + random(32) + session_id(var) +
                      cipher_suites(var) + compression(var)
             -> Extensions list
                 -> Extension type 0x0000 = SNI
                     -> Extract hostname
```

### Verifier-Safe Implementation

- Bounded loop for extension iteration (max 20)
- Stack buffer for hostname extraction (avoids variable-index writes to ring buffer memory)
- Validates protocol, content type, and handshake type at each step

SNI events are currently captured and logged but not yet integrated into policy evaluation.

---

## 6. Process Lifecycle Tracking

### Exec Events

**Hook point**: `sched:sched_process_exec` tracepoint

Captures:
- PID, parent PID, process name, executable filename
- **Argument capture**: Reads `arg_start` to `arg_end` from `task->mm` via `BPF_CORE_READ()`, stores NUL-separated argv (max 256 bytes)
- **Privacy**: `args_len` field tracks actual argv length, excluding environment variables that follow in the process address space

### Fork Events

**Hook point**: `sched:sched_process_fork` tracepoint

Captures: child PID, parent PID, process name. Fork events provide reliable parent PID from tracepoint args (more reliable than exec's ppid).

### Process Tree

An in-memory process tree (`pkg/proctree/`) maintains parent-child relationships:

- **Update**: On every fork/exec event
- **Query**: `GetAncestors(pid, maxDepth)` walks the tree upward, returning ancestor process names
- **Cycle detection**: Tracks visited PIDs to prevent infinite loops
- **Thread-safe**: RWMutex for concurrent reads during network event processing

The ancestry chain is used by the policy engine for **process chain blocking** (e.g., block `curl` when spawned by `npm`).

### Process Name Resolution

BPF captures the `comm` field (16 bytes, via `bpf_get_current_comm()`), but this can be spoofed via `prctl(PR_SET_NAME)`. For authoritative process identification, userspace reads `/proc/[pid]/exe` symlink via `utils.ResolveCommFromExe()`.

---

## 7. File Access Monitoring

**Hook point**: `syscalls:sys_enter_openat` tracepoint

### Detection Flow

1. BPF captures every `openat()` syscall: PID, process name, filename, flags
2. Userspace filters against configured monitored paths:
   - **Exact match**: `/etc/shadow` matches only that path
   - **Prefix match**: `/root/.ssh/` matches all files under that directory
3. Events that match are flagged in the report with `policy: "flag"`

### Sensitive File Examples

```yaml
monitored_paths:
  - "/etc/shadow"
  - "/etc/passwd"
  - "/root/.ssh/"
  - "/var/run/secrets/"           # Kubernetes secrets
  - "/home/*/.aws/credentials"
```

### Integration with Env Var Detection

When a process opens `/proc/*/environ`, the file monitor recognizes it as a special case and triggers environment variable scanning (see next section).

---

## 8. Environment Variable Detection

### Two-Phase Approach

kntrl detects sensitive environment variables through two complementary techniques:

### Phase 1: Exec-Time Scanning (Primary)

**Trigger**: `sched_process_exec` tracepoint (new process started)

When a process execs, kntrl immediately reads `/proc/<pid>/environ` and checks for monitored variable names:

```go
if eventTypeStr == "exec" && len(monitoredEnvVars) > 0 {
    if vars := utils.FindMatchingEnvVars(event.Pid, monitoredEnvVars); len(vars) > 0 {
        // Report with synthetic filename "[inherited]"
    }
}
```

**Why this works**: The kernel populates `/proc/<pid>/environ` during `execve()` with the full environment passed to the new process. This is readable immediately after exec completes, regardless of how the process later accesses its environment.

**What it catches**: Every standard env var access pattern:

| Language | Access Method | Syscall? | Detected? |
|----------|--------------|----------|-----------|
| Go | `os.Getenv("TOKEN")` | No (in-memory) | Yes - at exec |
| Python | `os.environ["TOKEN"]` | No (C runtime dict) | Yes - at exec |
| Bash | `$TOKEN` / `${TOKEN}` | No (shell table) | Yes - at exec |
| Zig | `std.os.getenv("TOKEN")` | No (environ pointer) | Yes - at exec |
| Node.js | `process.env.TOKEN` | No (V8 object) | Yes - at exec |

**Important**: This is **inheritance detection**, not access detection. It flags that the process *has access to* the variable, not that it read it. This is the correct security posture for supply chain scenarios.

### Phase 2: /proc/environ File Access (Secondary)

**Trigger**: `sys_enter_openat` tracepoint (file open)

When any process opens `/proc/*/environ` (cross-process environment inspection), the file event handler detects it:

```go
isEnvFile := len(monitoredEnvVars) > 0 && utils.IsEnvironFile(filename)
```

Pattern matched: `/proc/<pid>/environ` or `/proc/self/environ`

This catches techniques like `cat /proc/1234/environ` — a process explicitly inspecting another process's environment.

### Privacy Protection

Only variable **names** are logged, never values. The scanner reads `/proc/<pid>/environ`, parses `KEY=VALUE` pairs, and only reports which monitored keys are present.

---

## 9. Policy Engine (OPA/Rego)

### Architecture

kntrl embeds an OPA (Open Policy Agent) bundle with modular Rego rules. Configuration from YAML is converted to OPA data, and each network event is evaluated against the policy.

### Policy Evaluation Flow

```
Network Event
  |
  v
Build Input: {task_name, daddr, dport, domains, ancestors, proto}
  |
  v
Check Cache (30s TTL, key: task|addr|port|ancestors)
  |  hit -> return cached result
  v  miss
OPA Evaluation: data.kntrl.policy
  |
  +-> network_allowed (OR of all network rules)
  |     +-> is_allowed_hosts    (domain match)
  |     +-> is_allowed_ip       (exact IP match)
  |     +-> is_allowed_cidr     (CIDR range match)
  |     +-> is_process_profile  (per-process rules)
  |     +-> is_github_range     (GitHub Actions IPs)
  |     +-> is_local_ip_addr    (RFC 1918 ranges)
  |     +-> is_metadata         (cloud metadata endpoints)
  |
  +-> process_allowed (process in allowed list, or list empty)
  |
  +-> NOT ancestry_denied (process chain not in blocked list)
  |
  v
Final: network_allowed AND process_allowed AND NOT ancestry_denied
```

### Network Rules

| Rule | File | Logic |
|------|------|-------|
| Allowed Hosts | `is_allowed_hosts.rego` | Domain exact match or wildcard suffix (`.github.com` matches `api.github.com`) |
| Allowed IPs | `is_allowed_ip.rego` | Exact IP equality check |
| Allowed CIDRs | `is_allowed_cidr.rego` | `net.cidr_contains()` for CIDR ranges |
| Process Profiles | `is_process_profile.rego` | Per-process allowed hosts/CIDRs (e.g., npm can only reach registry.npmjs.org) |
| GitHub Ranges | `is_github_range.rego` | IP in GitHub Actions/API/Web CIDR ranges (from embedded or fetched metadata) |
| Local Ranges | `is_local_ip_addr.rego` | RFC 1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) |
| Metadata | `is_metadata.rego` | Cloud metadata endpoints (169.254.169.254, 168.63.129.16) |

### Process Ancestry Blocking

```rego
ancestry_denied if {
    chain := data.blocked_process_chains[_]
    chain.process == input.task_name
    every ancestor in chain.ancestors {
        ancestor == input.ancestors[_]
    }
}
```

Blocks a process if its name matches AND **all** specified ancestors appear in its ancestry chain. Example: block `curl` only when spawned from an `npm` process tree.

### Policy Caching

- **TTL**: 30 seconds
- **Key**: `task_name|destination_ip|port|ancestor1,ancestor2,...`
- **Storage**: `sync.Map` (lock-free concurrent access)
- **Invalidation**: Flushed on SIGHUP reload

---

## 10. Egress Filtering & Blocking

### Kernel-Level Enforcement

The `egress` CGroup SKB program implements packet-level filtering attached to `/sys/fs/cgroup`:

```
Packet arrives at cgroup egress
  |
  v
Parse IP header (IPv4 or IPv6)
  |
  v
Check source OR destination IP against allowed map
  |
  +-> Found in map -> ALLOW (return 0)
  |
  v
Check mode_map:
  +-> Monitor mode (0) -> ALLOW (log only)
  +-> Trace mode (1)   -> BLOCK (return 1, drop packet)
```

### Dynamic Allowlist Updates

When OPA policy evaluation returns **pass** for a connection, the destination IP is immediately added to the kernel's `allowed_ip_map`. Subsequent packets to the same IP are fast-pathed in kernel without userspace involvement.

### LRU Eviction

Allowlist maps use `BPF_MAP_TYPE_LRU_HASH` with 1024-entry capacity. Least-recently-used entries are automatically evicted when the map is full, ensuring bounded memory usage.

---

## 11. Established Connection Preloading

**Problem**: When kntrl attaches its cgroup egress filter, existing connections (e.g., SSH sessions) would be blocked because their IPs aren't in the allowlist yet.

**Solution**: Before attaching BPF programs, kntrl reads `/proc/net/tcp` and `/proc/net/tcp6` to discover all ESTABLISHED (state `01`) connections and pre-populates the allowed IP maps.

### IPv4 Preloading

Parses `/proc/net/tcp` hex format:
- Field 2: remote address as `XXXXXXXX:PPPP`
- Field 3: connection state (`01` = ESTABLISHED)
- Converts hex IP to uint32, inserts into `allowed_ip_map`

### IPv6 Preloading

Parses `/proc/net/tcp6` with byte-order handling:
- `/proc/net/tcp6` stores each 4-byte group in host (little-endian) order
- Reverses each group to network byte order for the BPF map key
- 32-char hex string -> `[16]byte` key

---

## 12. Self-Filtering

kntrl filters its own events at two levels:

### Kernel Level

kntrl's TGID is stored in `self_tgid_map`. BPF programs check this map and discard events from kntrl's own process, avoiding self-monitoring overhead and noise.

### Userspace Level

1. **Process events**: `selfPIDs()` builds a set of kntrl's PID + all descendant PIDs by walking the process event list. These are excluded from process tree output.
2. **File events**: Events with `comm == "kntrl"` are dropped before reporting.
3. **Network events**: Events with task name `"kntrl"` are skipped in the main event loop.

---

## 13. Live Policy Reload (SIGHUP)

kntrl supports hot-reloading configuration without restarting BPF programs:

```
SIGHUP received
  |
  v
Reload YAML config + directory rules
  |
  v
Rebuild OPA policy with new Rego rules
  |
  v
Update BPF maps:
  - allowed_ip_map (new IPs)
  - allowed_hosts_map (new domains)
  - allowed_ipv6_map (new IPv6 addresses)
  |
  v
Atomic pointer swap: policyPtr.Store(newPolicy)
  |
  v
Flush policy cache (invalidate 30s TTL entries)
```

Uses `atomic.Pointer[policy.Policy]` for lock-free reads in event processing goroutines. Reload errors are logged but don't crash the agent.

---

## 14. Reporting & Output

### Report Tables

kntrl generates five output sections when the agent stops:

| Table | Columns | Content |
|-------|---------|---------|
| **Network Report** | Pid, Comm, Proto, Domain, Destination Addr, Policy | All unique network connections with pass/block status |
| **DNS Report** | Domain, DNS Server | Deduplicated DNS queries with server info |
| **Process Tree** | Tree visualization or flat table | Fork/exec events with parent-child relationships |
| **Sensitive Access Report** | Pid, Comm, Files Accessed, Env Vars Detected | Aggregated file + env var detections per process |
| **File Access Table** | Pid, Comm, Filename, Policy, Env Vars | Raw file access events |

### Process Tree Visualization (--pretty)

Merges fork and exec events per PID, builds parent-child map, renders ASCII tree:

```
[1234] /usr/bin/make -j4
├── [1235] /bin/sh -c gcc foo.c
│   └── [1236] gcc foo.c
└── [1237] /bin/sh -c gcc bar.c
    └── [1238] gcc bar.c
```

### Persistent Output

All events are written as JSON (one per line) to the output file (`/tmp/kntrl.out` by default) with 64KB buffered writes for performance. Can be loaded later via `LoadAndPrint()`.

### Network Event Deduplication

Network events are deduplicated by MD5 hash of `address:port`, ensuring each unique destination appears only once in the report.

---

## 15. Webhook Alerting

### Architecture

```
Event occurs -> webhookClient.Send(event) -> channel (256 buffer) -> background goroutine -> HTTP POST
```

### Configuration

```yaml
webhooks:
  - url: "https://siem.example.com/events"
    headers:
      Authorization: "Bearer token"
    events: ["block"]        # "block", "pass", "all", "file_flag"
```

### Behavior

- Non-blocking: drops events if channel full (logs warning)
- 5-second HTTP timeout per request
- Sends JSON payload with event type, timestamp, and full event data
- Filter per webhook: only sends matching event types
- Two integration points: network events (pass/block) and file events (file_flag)

---

## 16. Configuration System

### Loading Precedence (highest to lowest)

1. **CLI flags**: `--allowed-hosts`, `--mode`, etc.
2. **Rules directory** (`--rules-dir`): All `*.yaml`/`*.yml` files merged
3. **Rules file** (`--rules-file`): Single YAML policy file
4. **Defaults**: Built-in defaults

### Merging Strategy

- **Lists**: Union + deduplicate
- **Booleans**: Override (non-nil takes precedence)
- **External Rego**: `*.rego` files from rules directory loaded alongside embedded bundle

### System Enrichment

During config-to-OPA conversion:
- Hostnames resolved to IPv4/IPv6 addresses
- DNS servers parsed from `/etc/resolv.conf`
- Loopback always added (127.0.0.1, ::1)
- GitHub meta IPs fetched from API (fallback to embedded data)
- CIDRs separated from individual IPs for efficient evaluation

---

## 17. Detection Coverage Matrix

| Technique | Detection Method | BPF Hook | Kernel/Userspace |
|-----------|-----------------|----------|------------------|
| Outbound TCP connection (IPv4) | Kprobe on `tcp_v4_connect` | Kprobe | Kernel capture, userspace policy |
| Outbound TCP connection (IPv6) | Kprobe on `tcp_v6_connect` | Kprobe | Kernel capture, userspace policy |
| Outbound UDP (IPv4) | Kprobe on `ip4_datagram_connect` | Kprobe | Kernel capture, userspace policy |
| Outbound UDP (IPv6) | Kprobe on `udpv6_sendmsg` | Kprobe | Kernel capture, userspace policy |
| DNS queries/responses | Kprobe on `skb_consume_udp` (port 53) | Kprobe | Kernel parse, userspace report |
| TLS destination (SNI) | CGroup SKB egress ClientHello parse | CGroup SKB | Kernel extraction |
| Process execution | Tracepoint `sched_process_exec` | Tracepoint | Kernel capture, userspace tree |
| Process forking | Tracepoint `sched_process_fork` | Tracepoint | Kernel capture, userspace tree |
| File access | Tracepoint `sys_enter_openat` | Tracepoint | Kernel capture, userspace filter |
| Env var inheritance | Read `/proc/<pid>/environ` at exec | Tracepoint (exec trigger) | Userspace scan |
| Cross-process env read | `/proc/*/environ` file open | Tracepoint (openat) | Kernel capture + userspace scan |
| Raw socket creation | Kprobe on `security_socket_create` | Kprobe | Kernel detection |
| Egress packet blocking | CGroup SKB egress filter | CGroup SKB | Kernel enforcement |
| Process ancestry chains | In-memory tree from fork/exec events | N/A | Userspace construction |
| Supply chain process blocking | Ancestry + OPA Rego evaluation | N/A | Userspace policy |

---

## Key Dependencies

| Library | Purpose |
|---------|---------|
| `cilium/ebpf` | eBPF program loading, ring buffers, map management |
| `open-policy-agent/opa` | Rego policy compilation and evaluation |
| `spf13/cobra` | CLI framework |
| `pterm/pterm` | Terminal table and tree rendering |
| `sirupsen/logrus` | Structured logging |

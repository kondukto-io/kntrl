![kntrl logo](./docs/img/kntrl_logo.png) <!-- markdownlint-disable-line first-line-heading -->

`kntrl` is an eBPF-based runtime security agent that monitors and controls network, process, DNS, TLS, and file activity on CI/CD runners and build pipelines. It hooks into kernel-level syscalls to enforce policies in real time — blocking supply-chain attacks, unauthorized network access, and anomalous process behaviour before they cause damage.

Refer to this [presentation](https://docs.google.com/presentation/d/1nmbqGfIxp9UyxlfT5EJyQsEWtQaXVoWD9Qjj1MJevuk/edit?usp=sharing) for a deeper look at the architecture.

## Features

- **Network monitoring & enforcement** — Intercepts IPv4/IPv6 TCP and UDP connections via eBPF kprobes. Allows or blocks based on destination IP, domain, CIDR range, and process identity.
- **DNS monitoring** — Captures DNS queries and responses at the kernel level. Tracks which domains each process resolves and restricts DNS server usage.
- **TLS SNI inspection** — Extracts Server Name Indication from TLS ClientHello packets via eBPF TC hooks for accurate domain-based blocking even before the connection completes.
- **Process ancestry tracking** — Monitors fork/exec events to build an in-memory process tree. Blocks connections when specific process chains are detected (e.g., block `curl` spawned by `npm`).
- **File access monitoring** — Tracks file open events on sensitive paths (e.g., `/etc/shadow`, `/root/.ssh/`).
- **Per-process network profiles** — Assign different allowed hosts per process (e.g., `npm` can only reach `registry.npmjs.org`).
- **OPA policy engine** — All policy decisions use Open Policy Agent with embedded Rego rules. Extend or override with custom `.rego` files.
- **Two operating modes** — `monitor` (log only) and `trace` (enforce and block).
- **Webhook alerting** — Send block/pass events to external endpoints in real time.
- **Established connection preloading** — Reads `/proc/net/tcp{,6}` at startup so existing SSH and database connections survive agent start.
- **SIGHUP live reload** — Reload YAML rules and flush policy caches without restarting.
- **Daemon mode** — Run in the background with PID file management.

### Security hardening

- **Process identity validation** — Overrides the BPF `comm` field (spoofable via `prctl`) with the real executable name from `/proc/[pid]/exe`.
- **Dot-boundary host matching** — `"github.com"` matches `sub.github.com` but NOT `evil-github.com`.
- **Raw socket monitoring** — Detects creation of `AF_PACKET`, `IPPROTO_RAW`, and `IPPROTO_ICMP` sockets.
- **No DNS auto-whitelisting** — DNS-resolved IPs require explicit policy approval before they enter the BPF allowlist.
- **LRU BPF maps** — Auto-evicting hash maps prevent map overflow under high load.

### Performance

- **Policy result caching** — Per-IP+task+ancestry TTL cache avoids redundant OPA evaluations (30s TTL).
- **Async DNS resolution** — Non-blocking worker goroutine for forward DNS cache population.
- **Buffered report I/O** — 64KB buffered writer reduces syscall overhead for report file writes.

## Installation

### Linux

`kntrl` is available as a downloadable binary from the [releases](https://github.com/kondukto-io/kntrl/releases) page. Download the pre-compiled binary and copy it to the desired location.

### Container Images

```
docker pull kondukto/kntrl:latest
```

To pull a specific version:

```
docker pull kondukto/kntrl:0.1.4
```

### Building from source

```bash
make generate   # compile eBPF programs (requires clang, llvm, libelf-dev)
make build      # build the Go binary to build/kntrl
```

## Quick start

Start the agent in monitor mode during your CI/CD job:

```yaml
- name: start kntrl agent
  run: sudo ./kntrl start --mode=monitor --allowed-hosts=download.kondukto.io,${{ env.GITHUB_ACTIONS_URL }} --allowed-ips=10.0.2.3 --daemonize
```

Stop and print the report:

```yaml
- name: stop kntrl agent
  run: sudo ./kntrl stop
```

Or with Docker:

```yaml
- name: kntrl agent
  run: sudo docker run --privileged \
    --pid=host \
    --network=host \
    --cgroupns=host \
    --volume=/sys/kernel/debug:/sys/kernel/debug:ro \
    --volume /tmp:/tmp \
    --rm docker.io/kondukto/kntrl:0.1.4 \
    start --mode=trace --allowed-hosts=kondukto.io,download.kondukto.io
```

## CLI reference

```
kntrl [command]

Commands:
  start       Start kntrl agent
  stop        Stop kntrl daemon and print reports
  status      Print kntrl daemon status
  completion  Generate shell autocompletion script
  help        Help about any command

Global flags:
  -v, --verbose   Enable verbose logging
      --version   Show version
```

### `kntrl start` flags

| Flag                     | Default          | Description                                                         |
| ------------------------ | ---------------- | ------------------------------------------------------------------- |
| `--mode`                 | `monitor`        | Operating mode: `monitor` (log only) or `trace` (enforce)           |
| `--allowed-hosts`        |                  | Comma-separated allowed hostnames (e.g., `example.com,.github.com`) |
| `--allowed-ips`          |                  | Comma-separated allowed IP addresses                                |
| `--allow-local-ranges`   | `true`           | Allow local IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)   |
| `--allow-github-meta`    | `false`          | Allow GitHub Actions IP ranges from api.github.com/meta             |
| `--allow-metadata`       | `false`          | Allow cloud metadata endpoints (169.254.169.254, 168.63.129.16)     |
| `--monitor-processes`    | `true`           | Enable process fork/exec monitoring                                 |
| `--rules-file`           |                  | Path to a YAML policy file                                          |
| `--rules-dir`            |                  | Path to a directory containing `.yaml` and/or `.rego` rule files    |
| `-o, --output-file-name` | `/tmp/kntrl.out` | Report output file                                                  |
| `--pretty`               | `false`          | Pretty-print process events as a tree                               |
| `--daemonize`            | `false`          | Run in the background                                               |

## YAML policy configuration

Use `--rules-file` to load a comprehensive YAML policy. This gives fine-grained control over network access, process monitoring, DNS servers, file access, process ancestry chains, per-process profiles, and webhook alerting.

```yaml
version: "1"
mode: trace
rules:
  network:
    allowed_hosts:
      - "github.com"
      - ".npmjs.org"
      - ".amazonaws.com"
    allowed_ips:
      - "10.0.0.0/8"
      - "172.16.0.0/12"
    allow_local_ranges: true
    allow_github_meta: true
    allow_metadata: false
    allowed_processes:
      - "curl"
      - "git"
      - "wget"
      - "docker"
    profiles:
      - process: "npm"
        allowed_hosts:
          - "registry.npmjs.org"
      - process: "pip"
        allowed_hosts:
          - "pypi.org"
          - "files.pythonhosted.org"
  process:
    enabled: true
    blocked_chains:
      - process: "curl"
        ancestors: ["npm"]
      - process: "wget"
        ancestors: ["pip"]
  dns:
    allowed_servers:
      - "8.8.8.8"
      - "8.8.4.4"
  file:
    enabled: false
    monitored_paths:
      - "/etc/shadow"
      - "/root/.ssh/"
      - "/proc/self/environ"
webhooks:
  - url: "https://your-siem.example.com/events"
    headers:
      Authorization: "Bearer <token>"
    filter: "block"
```

See `examples/policy-v2.yaml` for a full example.

### Live reload

Send `SIGHUP` to the running agent to reload the YAML rules file and flush policy caches without restarting:

```bash
kill -HUP $(cat /tmp/kntrl.pid)
```

## Process ancestry chain blocking

`kntrl` tracks process fork/exec events to build an in-memory process tree. When a network connection is made, `kntrl` walks the tree to determine the full ancestry chain of the connecting process. This ancestry is then evaluated against `blocked_chains` rules.

Each `blocked_chains` entry specifies a `process` name and a list of `ancestors`. If the process making the network connection matches `process` **and** every name in `ancestors` appears somewhere in its ancestry chain, the connection is **denied**.

This lets you write rules like "block `curl` if it was spawned (directly or indirectly) by `npm`":

```yaml
rules:
  process:
    enabled: true
    blocked_chains:
      - process: "curl"
        ancestors: ["npm"]
```

With this rule:

- `npm install` spawning `sh -> curl` to exfiltrate data is **blocked**
- A user running `curl github.com` directly from a shell is **allowed**

You can require multiple ancestors to be present:

```yaml
blocked_chains:
  - process: "sh"
    ancestors: ["npm", "node"]
```

The ancestry chain is also passed into OPA policy evaluation as `input.ancestors`, so you can write custom Rego rules against it.

## Per-process network profiles

Restrict which hosts a specific process can reach. For example, allow `npm` to reach only its registry:

```yaml
rules:
  network:
    profiles:
      - process: "npm"
        allowed_hosts:
          - "registry.npmjs.org"
      - process: "pip"
        allowed_hosts:
          - "pypi.org"
          - "files.pythonhosted.org"
```

If the connecting process matches a profile, **only** the hosts listed in that profile are allowed — the global allowed list does not apply.

## DNS monitoring

`kntrl` captures DNS queries and responses at the kernel level via eBPF kprobes. This provides:

- Correlation between resolved domains and destination IPs for accurate policy evaluation
- DNS server restriction — only allow queries to approved DNS servers
- Visibility into which processes resolve which domains

```yaml
rules:
  dns:
    allowed_servers:
      - "8.8.8.8"
      - "8.8.4.4"
```

DNS events are displayed in the report as a separate table:

```
Domain              | DNS Server
------------------------------------------
registry.npmjs.org  | 8.8.8.8
github.com          | 8.8.8.8
```

## TLS SNI inspection

`kntrl` uses eBPF TC (traffic control) hooks to inspect TLS ClientHello packets and extract the Server Name Indication (SNI) field. This allows domain-based policy enforcement even for encrypted connections, correlating the SNI with the network connection event.

## File access monitoring

Track access to sensitive files:

```yaml
rules:
  file:
    enabled: true
    monitored_paths:
      - "/etc/shadow"
      - "/root/.ssh/"
      - "/proc/self/environ"
```

File events appear in a separate report table:

```
Pid  | Comm    | Filename           | Flags
---------------------------------------------------
1234 | python  | /etc/shadow        | 0
```

## Webhook alerting

Send events to external systems (SIEM, Slack, etc.) in real time:

```yaml
webhooks:
  - url: "https://your-siem.example.com/events"
    headers:
      Authorization: "Bearer <token>"
    filter: "block" # "block", "pass", or "all"
```

Events are delivered asynchronously via buffered channels with a 5-second HTTP timeout per webhook.

## Open Policy Agent (OPA) rules

`kntrl` uses an embedded OPA policy engine. All policy rules live under `bundle/kntrl/` and are compiled into the binary. The policy evaluation flow:

1. Network event arrives from eBPF
2. Event is enriched with DNS domains, SNI, and process ancestry
3. OPA evaluates against all rules (allowed hosts, allowed IPs, local ranges, GitHub meta, process profiles, ancestry chains, custom rules)
4. Result: `pass` or `block`

### Built-in policies

| Policy               | Description                                                      |
| -------------------- | ---------------------------------------------------------------- |
| `is_allowed_hosts`   | Match domains against allowed host list with dot-boundary safety |
| `is_allowed_ip`      | Match IPs against explicit allowlist                             |
| `is_allowed_cidr`    | Match IPs against CIDR ranges                                    |
| `is_local_ip_addr`   | Allow RFC 1918 private ranges                                    |
| `is_github_range`    | Allow GitHub Actions infrastructure IPs                          |
| `is_metadata`        | Control cloud metadata endpoint access                           |
| `is_process_profile` | Per-process allowed hosts                                        |
| `ancestry`           | Block based on process ancestry chains                           |
| `custom`             | Placeholder for user-defined rules                               |

### Custom Rego rules

Add custom `.rego` files via `--rules-dir`:

```rego
package kntrl.network["my_custom_rule"]

import rego.v1

policy if {
    input.task_name == "curl"
    some ancestor in input.ancestors
    ancestor == "npm"
}
```

### Running Rego tests

```bash
make test-rego-local   # requires opa CLI
make test-rego         # runs in Docker
```

## Reporting

Events are logged to the output file (default `/tmp/kntrl.out`) in JSON format, one event per line:

```json
{
  "pid": 2806,
  "task_name": "curl",
  "proto": "tcp",
  "daddr": "140.82.114.22",
  "dport": 443,
  "domains": ["lb-140-82-114-22-iad.github.com"],
  "policy": "pass",
  "ancestors": ["bash"]
}
```

```json
{
  "pid": 3201,
  "task_name": "curl",
  "proto": "tcp",
  "daddr": "evil.example.com",
  "dport": 443,
  "domains": ["evil.example.com"],
  "policy": "block",
  "ancestors": ["sh", "npm", "node", "bash"]
}
```

When the agent stops, summary tables are printed:

```
Pid  | Comm    | Proto | Domain                          | Destination Addr   | Policy
---------------------------------------------------------------------------------------
2806 | curl    | tcp   | lb-140-82-114-22-iad.github.com | 140.82.114.22:443  | pass
---------------------------------------------------------------------------------------
3201 | curl    | tcp   | evil.example.com                | 93.184.216.34:443  | block
```

Use `--pretty` to display process events as a tree:

```
Process Tree

[1234] /bin/bash
├── [1235] npm install
│   └── [1236] sh -c curl http://evil.com
│       └── [1237] curl http://evil.com
└── [1240] git clone https://github.com/org/repo
```

## eBPF programs

kntrl attaches the following eBPF programs to kernel hooks:

| Hook                     | Type       | Purpose                         |
| ------------------------ | ---------- | ------------------------------- |
| `tcp_v4_connect`         | kprobe     | IPv4 TCP connection attempts    |
| `ip4_datagram_connect`   | kprobe     | IPv4 UDP connection attempts    |
| `tcp_v6_connect`         | kprobe     | IPv6 TCP connection attempts    |
| `udpv6_sendmsg`          | kprobe     | IPv6 UDP sends                  |
| `skb_consume_udp`        | kprobe     | DNS packet capture              |
| `inet_sock_set_state`    | tracepoint | TCP state change tracking       |
| `sched_process_exec`     | tracepoint | Process execution events        |
| `sched_process_fork`     | tracepoint | Process fork events             |
| `security_socket_create` | kprobe     | Raw socket creation detection   |
| TC classifier            | tc         | TLS SNI extraction from packets |

All event data flows through eBPF ring buffers for efficient kernel-to-userspace communication. BPF maps use LRU eviction to prevent overflow under high load.

## Testing

```bash
make test-unit          # unit tests (Docker)
make test-rego          # OPA policy tests (Docker)
make test-ebpf          # eBPF tests (requires Linux kernel)
make test-integration   # integration tests (requires Linux kernel)
make test-all           # all tests (Docker)

make test-unit-local    # unit tests (local, works on macOS)
make test-rego-local    # OPA policy tests (local, requires opa CLI)
```

## Contribution

Contributions to kntrl are welcome.
Feel free to join our Slack channel [https://kntrl.slack.com](https://kntrl.slack.com)

## License

Except for the eBPF code, all components are distributed under the [Apache License (version 2.0)](./LICENSE.md).

## More about Kondukto

`kntrl` is an open source project maintained by [Kondukto](https://kondukto.io).

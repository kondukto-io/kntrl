![kntrl logo](./docs/img/kntrl_logo_dark.svg) <!-- markdownlint-disable-line first-line-heading -->

`kntrl` is an eBPF-based runtime security agent for CI/CD runners and build pipelines. It observes network, process, DNS, TLS, and file activity and enforces network policies in the Linux kernel to limit unauthorized access during builds. Its protection depends on the configured policy and the scope of the monitored workload.

Refer to this [presentation](https://docs.google.com/presentation/d/1nmbqGfIxp9UyxlfT5EJyQsEWtQaXVoWD9Qjj1MJevuk/edit?usp=sharing) for a deeper look at the architecture.

## Features

- **Network monitoring & enforcement** — Observes IPv4/IPv6 connections and UDP sends through cgroup socket hooks, then enforces policy at cgroup egress. Decisions use destination IP, domain, CIDR range, and process identity.
- **DNS monitoring** — Captures DNS queries and responses at the kernel level. Tracks which domains each process resolves and restricts DNS server usage.
- **TLS SNI observation** — Extracts visible Server Name Indication from IPv4 TLS ClientHello packets on TCP port 443 at cgroup egress to enrich the domain cache.
- **Process ancestry tracking** — Monitors fork/exec events to build an in-memory process tree. Blocks connections when specific process chains are detected (e.g., block `curl` spawned by `npm`).
- **File access monitoring** — Tracks file open events on sensitive paths (e.g., `/etc/shadow`, `/root/.ssh/`).
- **Per-process network profiles** — Assign different allowed hosts per process (e.g., `npm` can only reach `registry.npmjs.org`).
- **OPA policy engine** — Evaluates network and process rules with embedded Rego policies. Extend with custom `.rego` files; the DNS port-53 exception is enforced separately in the kernel.
- **Two operating modes** — `monitor` (log only) and `trace` (enforce and block).
- **Webhook alerting** — Send block/pass events to external endpoints in real time.
- **Socket-scoped enforcement** — A policy grant permits one kernel socket and destination address/port/protocol. Another socket connecting to the same IP needs its own approval.
- **SIGHUP live reload** — Reload YAML rules and flush policy caches without restarting.
- **Daemon mode** — Run in the background with PID file management.

### Security hardening

- **Process identity validation** — Overrides the BPF `comm` field (spoofable via `prctl`) with the real executable name from `/proc/[pid]/exe`.
- **Dot-boundary host matching** — `"github.com"` matches `sub.github.com` but NOT `evil-github.com`.
- **Raw socket monitoring** — Detects creation of `AF_PACKET`, `IPPROTO_RAW`, and `IPPROTO_ICMP` sockets.
- **No DNS auto-whitelisting** — DNS-resolved IPs require explicit policy approval before they enter the BPF allowlist.
- **LRU BPF maps** — Auto-evicting hash maps prevent map overflow under high load.
- **Restricted DNS exception** — TCP/UDP port 53 is permitted only to configured resolvers. Cloudflare and Google are the defaults; explicit resolver lists replace them.
- **Release verification** — The release workflow signs the binary checksum manifest with keyless Cosign and publishes GitHub artifact attestations. Verify both the signature and binary checksums before execution.

### Performance

- **Policy result caching** — Per-IP+task+ancestry TTL cache avoids redundant OPA evaluations (30s TTL).
- **Async DNS resolution** — Non-blocking worker goroutine for forward DNS cache population.
- **Buffered report I/O** — 64KB buffered writer reduces syscall overhead for report file writes.

## Installation

### Runtime requirements

The agent requires Linux, cgroup v2, kernel BTF and the eBPF hooks used by its
sensors. The current binary requires root; a container must also have permission
to load and attach BPF programs and access the target cgroup and process metadata.
Container UID 0 alone does not grant those host permissions.

For a Kubernetes GitLab runner, an unprivileged, non-root build container cannot
start the agent on its own. Deployment requires runner or cluster administrator
support. The current implementation does not provide a ready-to-use, isolated
per-build sidecar: `--cgroup-path` scopes cgroup network hooks, while process and
file sensors are not all restricted to that subtree. Running in a pod does not
by itself limit every sensor to that pod.

### Linux

Download a selected tag from the [releases](https://github.com/kondukto-io/kntrl/releases) page:

| Asset | Purpose |
| --- | --- |
| `kntrl.amd64` | Linux x86-64 binary |
| `kntrl_arm64.arm64` | Linux ARM64 binary |
| `checksums.txt` | SHA256 digests of both binaries |
| `checksums.txt.sigstore.json` | Cosign signature bundle for the checksum manifest |

The bundle is available only for releases produced by the new signing workflow;
older releases are not retroactively signed. Follow the
[download and verification instructions](docs/releases.md#verify-before-running)
to download all four assets and check the exact release workflow/tag identity,
the GitHub Actions OIDC issuer, and both binary checksums. Install only after
both signature and checksum verification succeed:

```bash
# From the verified download directory, choose your architecture:
sudo install -m 0755 ./kntrl.amd64 /usr/local/bin/kntrl
# ARM64: sudo install -m 0755 ./kntrl_arm64.arm64 /usr/local/bin/kntrl
```

### Release integrity

Tagged releases run CI before building. The build job has read-only repository
permissions; a separate job signs `checksums.txt` using GitHub Actions OIDC and
Cosign, verifies the signature, attests the assets, and publishes them. No
long-lived signing key is stored. Signing or verification failures stop publication.

The signature authenticates the checksum manifest; checking the manifest binds
the downloaded binaries to that signature. See [release integrity](docs/releases.md)
for the trust model and commands. GitHub Action and GitLab installers must adopt
this verification separately; release signing alone does not make their installs
verify signatures automatically.

### Containers

The current release workflow publishes binaries, checksums, and the signature
bundle; it does not publish Docker images. The repository's [Dockerfile](Dockerfile)
can package a verified binary named `kntrl` in its build context. Container
deployment still requires the host permissions and visibility described above.

### Building from source

```bash
make generate   # compile eBPF programs (defaults to clang-19)
make build      # build the Go binary to build/kntrl
```

Build on Linux with the Go version in [go.mod](go.mod), clang/LLVM, libelf headers,
and `wget` available. `make build` downloads GitHub metadata for the policy bundle.

## Quick start

Start the agent in monitor mode during your CI/CD job:

```yaml
- name: start kntrl agent
  run: sudo kntrl start --mode=monitor --allowed-hosts=github.com,download.kondukto.io --daemonize
```

Stop and print the report:

```yaml
- name: stop kntrl agent
  if: always()
  run: sudo kntrl stop
```

Monitor mode logs decisions and does not block traffic. Before enabling `trace`,
configure the workload's required destinations and DNS resolvers, and choose the
[network enforcement scope](#network-enforcement-scope). The default allows local
IP ranges; use `--allow-local-ranges=false` when those should require explicit rules.

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
| `--cgroup-path`          | `/sys/fs/cgroup`  | Existing cgroup v2 subtree for network enforcement; does not create or move the workload |
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

See [examples/policy-v2.yaml](examples/policy-v2.yaml) for a full example. DNS
resolvers are configured through `rules.dns.allowed_servers`; there is no
dedicated DNS server CLI flag. The explicit Google resolver list above replaces
the built-in Cloudflare and Google defaults.

### Network enforcement scope

In `trace` mode, start the agent before the workload creates its sockets. Existing
connections are no longer automatically trusted. TCP may wait for its first SYN
retry while OPA evaluates a new socket; non-DNS UDP applications must retry their
initial datagram. SIGHUP revokes existing socket grants, so reconnect workloads
after reloading their network policy.

Use `--cgroup-path=/sys/fs/cgroup/<workload>` to enforce a dedicated cgroup subtree
while keeping the agent and runner/SSH control plane outside it. The default is
the root cgroup; applying trace mode there also restricts existing management
connections. A socket grant follows the socket if a privileged workload passes
its file descriptor to another process. Run untrusted workloads without host
administration privileges. Fragments, non-TCP/UDP packets, and IPv6 extension
headers are denied in trace mode; monitor mode remains pass-through.

For non-DNS traffic, process allowlists and blocked ancestry chains must also
pass even when an IP, CIDR, local range, or GitHub range is allowed. Resolver
traffic on port 53 uses its separate destination allowlist.

### Live reload

Send `SIGHUP` to the running agent to reload the YAML rules file and flush policy caches without restarting:

```bash
sudo kill -HUP "$(cat /var/run/kntrl.pid)"
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
- A user running `curl github.com` directly from a shell is not blocked by this
  ancestry rule; the network and process rules must still allow it.

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

In trace mode, TCP and UDP destination port 53 are allowed **only** to configured
resolver addresses, for both IPv4 and IPv6. General host/IP grants do not override
this restriction, and a DNS resolver does not receive permission on other ports.

When `rules.dns.allowed_servers` is omitted, defaults are Cloudflare
(`1.1.1.1`, `1.0.0.1`, `2606:4700:4700::1111`, `2606:4700:4700::1001`) and
Google (`8.8.8.8`, `8.8.4.4`, `2001:4860:4860::8888`, `2001:4860:4860::8844`).
An explicit list replaces these defaults and inherited lists; `allowed_servers: []`
disables the exception. Add your corporate resolver or local DNS stub explicitly
if the workload uses one. kntrl does not rewrite system DNS settings or derive
permissions from `/etc/resolv.conf`.

CI integrations may supply their own explicit resolver lists. For a Kubernetes
runner, configure the actual cluster DNS or NodeLocal DNS address used by the
build pod; a public resolver list alone does not authorize that address. Keep any
public resolvers you need in the same explicit list.

This restricts resolver destinations; it does not validate DNS payloads or prevent
DNS tunneling through an approved resolver. DNS-over-HTTPS/TLS uses ordinary
network policy, not the port-53 exception.

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

`kntrl` inspects IPv4 TCP port 443 traffic at cgroup egress for a visible TLS
ClientHello SNI field and caches the hostname-to-IP association. This is a
best-effort observation, not TLS decryption or a guarantee that SNI authorizes
the initial connection: the TCP handshake precedes ClientHello, and the socket
must already have network permission to complete it.

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
| `cgroup/connect4`, `cgroup/connect6` | cgroup socket address | IPv4/IPv6 connection attempts and socket identity |
| `cgroup/sendmsg4`, `cgroup/sendmsg6` | cgroup socket address | IPv4/IPv6 UDP sends and socket identity |
| `cgroup_skb/egress`      | cgroup skb | Socket/destination grants, resolver restrictions, and SNI observation |
| `skb_consume_udp`        | kprobe     | DNS packet capture              |
| `sched_process_exec`     | tracepoint | Process execution events        |
| `sched_process_fork`     | tp_btf     | Process fork events             |
| `security_socket_create` | kprobe     | Raw socket creation detection   |

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
go test -count=1 -race ./tests/release/... # release manifest and signing workflow checks
```

CI also validates workflows and GoReleaser configuration, runs vet/Nilaway and
unit tests, and exercises kernel DNS and socket isolation on Linux. Govulncheck
reports module-level findings and blocks on reachable vulnerabilities across the
application. Release workflow tests stub Cosign; live OIDC signing and signature
verification run when a release tag triggers the workflow.

## Contribution

Contributions to kntrl are welcome.
Feel free to join our Slack channel [https://kntrl.slack.com](https://kntrl.slack.com)

## License

Except for the eBPF code, all components are distributed under the [Apache License (version 2.0)](./LICENSE).

## More about Invicti

This project is maintained by [Invicti](https://invicti.com).

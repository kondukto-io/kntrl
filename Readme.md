![kntrl logo](./docs/img/kntrl_logo.png) <!-- markdownlint-disable-line first-line-heading -->

`kntrl` is an eBPF based runtime agent that monitors and prevents anomalous behaviour defined by you on your pipeline. kntrl achieves this by monitoring kernel calls, and denying access as soon as your defined behaviour is detected. Refer to this [presentation](https://docs.google.com/presentation/d/1nmbqGfIxp9UyxlfT5EJyQsEWtQaXVoWD9Qjj1MJevuk/edit?usp=sharing) to dive deeper into how we are achieving what kntrl does.

It can work as a single binary (`kntrl`) or with a docker runner (`docker.io/kondukto/kntrl:0.1.2`).

## Installation

### Linux

`kntrl` is available as downloadable binaries from the releases page. Download the pre-compiled binary from the `releases` page and copy to the desired location.

### Container Images

We provide ready to use Docker container images. To pull the latest image:

```
docker pull kondukto/kntrl:latest
```

To pull a specific version:

```
docker pull kondukto/kntrl:0.1.4
```

## Using kntrl

You can start using kntrl agent by simply running the following command, if you pass `--daemonize` flag the process will run in the background:

```yaml
- name: start kntrl agent
  run: sudo ./kntrl start --mode=monitor --allowed-hosts=download.kondukto.io,${{ env.GITHUB_ACTIONS_URL }} --allowed-ips=10.0.2.3  --daemonize
```

to stop `kntrl` and print reports:

```yaml
- name: stop kntrl agent
  run: sudo ./kntrl stop
```

OR with the docker:

```yaml
- name: kntrl agent
  run: sudo docker start --privileged \
    --pid=host \
    --network=host \
    --cgroupns=host \
    --volume=/sys/kernel/debug:/sys/kernel/debug:ro \
    --volume /tmp:/tmp \
    --rm docker.io/kondukto/kntrl:0.1.2 run --mode=trace --allowed-hosts=kondukto.io,download.kondukto.io
```

This action will deploy kntrl into any GitHub Actions build.

## Usage

The `kntrl` agent is self explanatory and it comes with a help command. Simply run `--help` flag after each command/subcommand.

```
 ./kntrl --help
Usage:
  kntrl [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  start       Start kntrl
  status      Print kntrl daemon status
  stop        Stop kntrl daemon

Flags:
  -h, --help      help for kntrl
  -v, --verbose   more logs
      --version   version for kntrl

Use "kntrl [command] --help" for more information about a command.
Runtime security tool to control and monitor egress/ingress traffic in CI/CD runners
```

The agent supports the following parameters:

```
| Name                 | Default          | Description                                                         |
| -------------------- | ---------------- | ------------------------------------------------------------------- | --- |
| `mode`               | monitor          | kntrl for detected behaviours (monitor or prevent/trace)            |
| `allowed-hosts`      |                  | allowed host list. (example.com, .github.com)                       |
| `allowed-ips`        |                  | allowed IP list. (192.168.0.100, 1.1.1.1)                           |
| `allow-local-ranges` | true             | allow access to local IP ranges                                     |
| `allow-github-meta`  | false            | allow access to GitHub meta IP ranges (https://api.github.com/meta) |
| `output-file`        | `/tmp/kntrl.out` | report file                                                         |     |
```

### Running kntrl on monitoring mode

```yaml
- name: kntrl agent
  run: sudo docker start --privileged \
  --pid=host \
  --network=host \
  --cgroupns=host \
  --volume=/sys/kernel/debug:/sys/kernel/debug:ro \
  --volume /tmp:/tmp \
  --rm docker.io/kondukto/kntrl:0.1.2 \
  --mode=monitor
```

### Running kntrl on prevent mode

```yaml
- name: kntrl agent
  run: sudo docker start --privileged \
  --pid=host \
  --network=host \
  --cgroupns=host \
  --volume=/sys/kernel/debug:/sys/kernel/debug:ro \
  --volume /tmp:/tmp \
  --rm docker.io/kondukto/kntrl:0.1.2 \
  --mode=trace --allowed-hosts=download.kondukto.io, .github.com
```

## YAML Policy Configuration

`kntrl` supports a YAML-based policy configuration file via the `--rules-file` flag. This gives you fine-grained control over network access, process monitoring, DNS servers, file access, and process ancestry chains.

```yaml
version: "1"
mode: trace
rules:
  network:
    allowed_hosts:
      - "github.com"
      - ".npmjs.org"
    allowed_ips:
      - "10.0.0.0/8"
    allow_local_ranges: true
    allow_github_meta: true
    allow_metadata: false
    allowed_processes:
      - "curl"
      - "git"
    profiles:
      - process: "npm"
        allowed_hosts:
          - "registry.npmjs.org"
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
  file:
    enabled: false
    monitored_paths:
      - "/etc/shadow"
```

See `examples/policy-v2.yaml` for a full example.

### Process Ancestry Chain Blocking

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

You can require multiple ancestors to be present. For example, blocking `sh` only when both `npm` and `node` are in the ancestry:

```yaml
blocked_chains:
  - process: "sh"
    ancestors: ["npm", "node"]
```

The ancestry chain (as `ancestors` in the report JSON) is also passed into OPA policy evaluation, so you can write custom Rego rules against `input.ancestors`.

## Open Policy Agent (OPA) Rules

`kntrl` supports an OPA-based policy engine to determine whether the event should be blocked or not. All the policy rules are stored under the bundle/kntrl/ directory.

An example rego rule:

```
package kntrl.network["is_local_ip_addr"]

import rego.v1

policy if {
        ipaddr := input.daddr
        local_ranges := ["192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8", "0.0.0.0/32"]
        net.cidr_contains(local_ranges[_], ipaddr)
        data.allow_local_ip_ranges == true
}
```

## Reporting

Each event will be logged in the output file. The default report file location is `/tmp/kntrl.out`.

Here is an example report:

```
{
  "pid": 2806,
  "task_name": "curl",
  "proto": "tcp",
  "daddr": "140.82.114.22",
  "dport": 443,
  "domains": [
    "lb-140-82-114-22-iad.github.com."
  ],
  "policy": "pass",
  "ancestors": ["bash"]
}
{
  "pid": 3201,
  "task_name": "curl",
  "proto": "tcp",
  "daddr": "evil.example.com",
  "dport": 443,
  "domains": [
    "evil.example.com."
  ],
  "policy": "block",
  "ancestors": ["sh", "npm", "node", "bash"]
}
{
  "pid": 2806,
  "task_name": "curl",
  "proto": "udp",
  "daddr": "127.0.0.1",
  "dport": 53,
  "domains": [
    "localhost"
  ],
  "policy": "pass"
}
```

When process ancestry tracking is active, the `ancestors` field contains the chain of parent process names (parent, grandparent, etc.). This field is omitted when the ancestry is empty.

or

```
Pid  | Comm    | Proto | Domain                          | Destination Addr   | Policy
------------------------------------------------------------------------------------
2806 | curl    | tcp   | lb-140-82-114-22-iad.github.com | 140.82.114.22:443  | pass
------------------------------------------------------------------------------------
2806 | curl    | tcp   | ww-in-f95.1e100.net             | 142.251.167.95:443 | block
------------------------------------------------------------------------------------
2806 | curl    | udp   | localhost                       | 127.0.0.1:53       | pass
------------------------------------------------------------------------------------
```

## Contribution

Contributions to kntrl are welcome.
Feel free to join our slack channel [https://kntrl.slack.com](https://kntrl.slack.com)

## License

Except for the eBPF code, all components are distributed under the [Apache License (version 2.0)](./LICENSE.md).

## More about Kondukto

`kntrl` is an open source project maintained by [Kondukto](https://kondukto.io).

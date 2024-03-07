# Kntrl - An eBPF agent to monitor and prevent threats in the CI/CD pipelines

`kntrl` is an eBPF based runtime agent that monitors and prevents anomalous behaviour defined by you on your pipeline. kntrl achieves this by monitoring kernel calls, and denying access as soon as your defined behaviour is detected. Refer to this [presentation](https://docs.google.com/presentation/d/1nmbqGfIxp9UyxlfT5EJyQsEWtQaXVoWD9Qjj1MJevuk/edit?usp=sharing) to dive deeper into how we are achieving what kntrl does.

It can work as a single binary (`kntrl`) or with a docker runner (`docker.io/kondukto/kntrl:0.1.0`).

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
docker pull kondukto/kntrl:0.1.0
```

## Using kntrl

You can start using kntrl agent by simply running the following command:

```yaml
- name: kntrl agent
  run: sudo ./kntrl run --mode=monitor --hosts=download.kondukto.io,${{ env.GITHUB_ACTIONS_URL }} 
```

OR with the docker:

```yaml
- name: kntrl agent
  run: sudo docker run --privileged \
    --pid=host \
    --network=host \
    --cgroupns=host \
    --volume=/sys/kernel/debug:/sys/kernel/debug:ro \
    --volume /tmp:/tmp \
    --rm docker.io/kondukto/kntrl:0.1.0 run --mode=trace --hosts=kondukto.io,download.kondukto.io 
```

This action will deploy kntrl into any GitHub Actions build.

## Usage
The `kntrl` agent is self explanatory and it comes with a help command. Simply run `--help` flag after each command/subcommand.

```
 ./kntrl --help
Runtime security tool to control and monitor egress/ingress traffic in CI/CD runners

Usage:
  tracer [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  run         Starts the TCP/UDP tracer

Flags:
  -h, --help      help for tracer
  -v, --verbose   more logs

Use "tracer [command] --help" for more information about a command.
```

The agent supports the following parameters:

| Name                     | Default               | Description                                                                                                                                                                                                                                                                                                                                                               |
| ------------------------ | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mode`                   |   monitor                    | kntrl for detected behaviours (monitor or prevent/trace)                                                                                                                                                                                                                                                                                                                  |
| `hosts`                  |                       | allowed host list. IP or hostname (192.168.0.100, example.com, .github.com)                                                                                                                                                                                                                                                                                                                                                         |
| `level`                  |   info              | level of detail for logging (info, debug)                                                                                                                                                                                                                                                                                                                               |
| `output-file`                  | `/tmp/kntrl.out`                       | report file |                                                                                                                                                                                                                                     |

### Running kntrl on monitoring mode

```yaml
- name: kntrl agent
  run: sudo docker run --privileged \
  --pid=host \
  --network=host \
  --cgroupns=host \
  --volume=/sys/kernel/debug:/sys/kernel/debug:ro \
  --volume /tmp:/tmp \
  --rm docker.io/kondukto/kntrl:0.1.0 \
  --mode=monitor 
```

### Running kntrl on prevent mode

```yaml
- name: kntrl agent
  run: sudo docker run --privileged \
  --pid=host \
  --network=host \
  --cgroupns=host \
  --volume=/sys/kernel/debug:/sys/kernel/debug:ro \
  --volume /tmp:/tmp \
  --rm docker.io/kondukto/kntrl:0.1.0 \
  --mode=trace --hosts=download.kondukto.io, .github.com  
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
  "policy": "pass"
}
{
  "pid": 2806,
  "task_name": "curl",
  "proto": "tcp",
  "daddr": "142.251.167.95",
  "dport": 443,
  "domains": [
    "ww-in-f95.1e100.net."
  ],
  "policy": "block"
}
{
  "pid": 921,
  "task_name": "python3",
  "proto": "udp",
  "daddr": "168.63.129.16",
  "dport": 443,
  "domains": [
    "-"
  ],
  "policy": "pass"
}
```

or 

```
Pid  | Comm    | Proto | Domain                          | Destination Addr   | Policy
------------------------------------------------------------------------------------
2806 | curl    | tcp   | lb-140-82-114-22-iad.github.com | 140.82.114.22:443  | pass
------------------------------------------------------------------------------------
2806 | curl    | tcp   | ww-in-f95.1e100.net             | 142.251.167.95:443 | block
------------------------------------------------------------------------------------
921  | python3 | udp   | 168.63.129.16                   | 142.251.167.95:443 | pass
------------------------------------------------------------------------------------
```

## Contribution

Contributions to kntrl are welcome.

## License

[GPLv3](./LICENSE.md)

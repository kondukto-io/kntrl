# Monitor and prevent threats in your pipeline

kntrl is a runtime agent that monitors and prevents anomalous behaviour defined by you on your pipeline using eBPF. kntrl achieves this by monitoring kernel calls, and denying access as soon as your defined behaviour is detected.

## Using kntrl

You can start using kntrl by adding docker command or kntrl binary to your pipeline with the following;

```yaml
- name: kntrl agent
  run: sudo docker run --privileged --pid=host --network=host --cgroupns=host --volume=/sys/kernel/debug:/sys/kernel/debug:ro --volume /tmp:/tmp --volume /etc/resolv.conf:/etc/resolv.conf --rm docker.io/kondukto/kntrl:0.0 run --mode=trace --hosts=kondukto.io,download.kondukto.io --level=debug
```

OR

```yaml
- name: kntrl agent
  run: sudo ./kntrl run --mode=monitor --hosts=kondukto.io,download.kondukto.io,${{ env.GITHUB_ACTIONS_URL }}--level=debug
```

This action will deploy kntrl into any GitHub Actions build.

## Usage

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
  run: sudo docker run --privileged --pid=host --network=host --cgroupns=host --volume=/sys/kernel/debug:/sys/kernel/debug:ro --volume /tmp:/tmp --volume /etc/resolv.conf:/etc/resolv.conf --rm docker.io/kondukto/kntrl:0.0 --mode=allow --hosts=kondukto.io,download.kondukto.io --level=debug &
```

### Running kntrl on prevent mode

```yaml
- name: kntrl agent
  run: sudo docker run --privileged --pid=host --network=host --cgroupns=host --volume=/sys/kernel/debug:/sys/kernel/debug:ro --volume /tmp:/tmp --volume /etc/resolv.conf:/etc/resolv.conf --rm docker.io/kondukto/kntrl:0.0 --mode=allow --hosts=kondukto.io,download.kondukto.io --level=debug &
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
```

or 

```
Pid  | Comm | Proto | Domain                           | Destination Addr   | Policy
------------------------------------------------------------------------------------
2806 | curl | tcp   | lb-140-82-114-22-iad.github.com. | 140.82.114.22:443  | pass
------------------------------------------------------------------------------------
2806 | curl | tcp   | ww-in-f95.1e100.net.             | 142.251.167.95:443 | block
------------------------------------------------------------------------------------
```

## Contribution

Contributions to kntrl are welcome.

## License

[GPLv3](./LICENSE.md)

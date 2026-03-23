package kntrl

import rego.v1

default policy = false

# Network is allowed if any network rule passes
network_allowed if {
	data.kntrl.network[_].policy
}

# Process is allowed if no process allowlist is defined
process_allowed if {
	not data.allowed_processes
}

# Process is allowed if the allowlist is empty
process_allowed if {
	count(data.allowed_processes) == 0
}

# Process is allowed if the task name is in the allowlist
process_allowed if {
	input.task_name == data.allowed_processes[_]
}

# Process is allowed if the destination is an explicitly allowed host.
# This matches the BPF cgroup filter: IPs resolved from allowed_hosts are
# pre-populated in the kernel allowlist for ALL processes, so OPA must agree.
process_allowed if {
	data.kntrl.network["is_allowed_hosts"].policy
}

# Final policy: network and process must be allowed, ancestry must not be denied
policy if {
	network_allowed
	process_allowed
	not ancestry_denied
}

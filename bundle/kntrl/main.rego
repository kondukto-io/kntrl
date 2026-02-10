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

# Final policy: both network and process must be allowed
policy if {
	network_allowed
	process_allowed
}

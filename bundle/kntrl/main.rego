package kntrl

import rego.v1

default policy = false

# A process profile restricts rather than expands global network permissions.
has_process_profile if {
	input.task_name == data.process_profiles[_].process
}

network_allowed if {
	has_process_profile
	data.kntrl.network["is_process_profile"].policy
}

# Global rules apply only when no process profile is configured.
network_allowed if {
	not has_process_profile
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

# Final policy: network and process must be allowed, ancestry must not be denied
policy if {
	network_allowed
	process_allowed
	not ancestry_denied
}

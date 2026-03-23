package kntrl.network["is_process_profile"]

import rego.v1

# Allow if process matches a profile and the destination host matches
policy if {
	profile := data.process_profiles[_]
	input.task_name == profile.process
	some host in input.domains
	allowed := profile.allowed_hosts[_]
	_host_matches(host, allowed)
}

_host_matches(host, pattern) if {
	host == pattern
}

_host_matches(host, pattern) if {
	startswith(pattern, ".")
	endswith(host, pattern)
}

_host_matches(host, pattern) if {
	not startswith(pattern, ".")
	endswith(host, concat("", [".", pattern]))
}

# Allow if process matches a profile and the destination IP is in an allowed CIDR
policy if {
	profile := data.process_profiles[_]
	input.task_name == profile.process
	net.cidr_contains(profile.allowed_cidrs[_], input.daddr)
}

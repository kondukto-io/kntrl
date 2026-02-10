package kntrl.network["is_process_profile"]

import rego.v1

# Allow if process matches a profile and the destination host matches
policy if {
	profile := data.process_profiles[_]
	input.task_name == profile.process
	some host in input.domains
	endswith(host, profile.allowed_hosts[_])
}

# Allow if process matches a profile and the destination IP is in an allowed CIDR
policy if {
	profile := data.process_profiles[_]
	input.task_name == profile.process
	net.cidr_contains(profile.allowed_cidrs[_], input.daddr)
}

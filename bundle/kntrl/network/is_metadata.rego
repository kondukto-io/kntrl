package kntrl.network["is_metadata"]

import rego.v1

metadata_cidrs := ["169.254.169.254/32", "168.63.129.16/32"]

policy if {
	net.cidr_contains(metadata_cidrs[_], input.daddr)
	data.allow_metadata == true
}

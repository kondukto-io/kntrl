package kntrl.network["is_allowed_cidr"]

import rego.v1

policy if {
	ipaddr := input.daddr
	net.cidr_contains(data.allowed_cidrs[_], ipaddr)
}

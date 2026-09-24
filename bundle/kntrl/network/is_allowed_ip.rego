package kntrl.network["is_allowed_ip"]

import rego.v1

policy if {
	data.allowed_ip_addr[_] == input.daddr
}

policy if {
	data.allowed_ipv6s[_] == input.daddr
}

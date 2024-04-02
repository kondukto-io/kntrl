package kntrl.network["is_local_ip_addr"]

import rego.v1

policy if {
	ipaddr := input.daddr
	local_ranges := ["192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8", "0.0.0.0/32"]
	net.cidr_contains(local_ranges[_], ipaddr)
	data.allow_local_ip_ranges == true
}

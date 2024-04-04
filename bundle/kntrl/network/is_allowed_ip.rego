package kntrl.network["is_allowed_ip"]

import rego.v1

policy if {
        ipaddr := input[_]
        data.allowed_ip_addr[_] == ipaddr
}

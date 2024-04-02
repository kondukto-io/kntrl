package kntrl.network["is_allowed_hosts"]

import rego.v1

policy if {
        hosts := input[_]

        some host in hosts
        endswith(host, data.allowed_hosts[_])
}

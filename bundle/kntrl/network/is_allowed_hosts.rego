package kntrl.network["is_allowed_hosts"]

import rego.v1

policy if {
        hosts := input[_]

        some host in hosts
        allowed := data.allowed_hosts[_]
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

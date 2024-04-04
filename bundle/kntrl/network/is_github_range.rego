package kntrl.network["is_github_range"]

import rego.v1
import data.assets.github

ranges := github.actions

policy if {
        ipaddr := input[_]
	net.cidr_contains(ranges[_], ipaddr)
	data.allow_github_meta == true
}

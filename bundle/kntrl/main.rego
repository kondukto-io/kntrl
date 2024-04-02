package kntrl

import rego.v1

default policy = false

#policy if data.kntrl.network[_].policy
policy if {
	data.kntrl.network[_].policy
}

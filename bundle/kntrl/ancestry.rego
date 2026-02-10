package kntrl

import rego.v1

default ancestry_denied = false

ancestry_denied if {
	chain := data.blocked_process_chains[_]
	chain.process == input.task_name
	every ancestor in chain.ancestors {
		ancestor == input.ancestors[_]
	}
}

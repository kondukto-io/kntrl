package kntrl

import rego.v1

# Block network connections originating from the "ls" command.
ancestry_denied if {
	input.task_name == "ls"
}

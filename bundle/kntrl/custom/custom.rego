package kntrl.custom["custom"]

import rego.v1

default policy = false 

policy if {
	input.task_name == "curl"
}

#policy if {
#	input.task_name == "ping"
#}

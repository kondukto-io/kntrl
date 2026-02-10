package kntrl

import rego.v1

# curl with npm in ancestry should be denied
test_curl_with_npm_ancestor_denied if {
	ancestry_denied with input as {"task_name": "curl", "ancestors": ["sh", "npm", "bash"]}
		with data.blocked_process_chains as [{"process": "curl", "ancestors": ["npm"]}]
}

# curl without npm in ancestry should not be denied
test_curl_without_npm_ancestor_not_denied if {
	not ancestry_denied with input as {"task_name": "curl", "ancestors": ["bash"]}
		with data.blocked_process_chains as [{"process": "curl", "ancestors": ["npm"]}]
}

# npm itself making a connection should not be denied (npm is not the process in the chain)
test_npm_itself_not_denied if {
	not ancestry_denied with input as {"task_name": "npm", "ancestors": ["bash"]}
		with data.blocked_process_chains as [{"process": "curl", "ancestors": ["npm"]}]
}

# chain requires both npm and sh, only npm present -> not denied
test_multiple_required_ancestors if {
	not ancestry_denied with input as {"task_name": "curl", "ancestors": ["npm", "bash"]}
		with data.blocked_process_chains as [{"process": "curl", "ancestors": ["npm", "sh"]}]
}

# no blocked_chains configured -> not denied
test_no_blocked_chains if {
	not ancestry_denied with input as {"task_name": "curl", "ancestors": ["npm"]}
		with data.blocked_process_chains as []
}

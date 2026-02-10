package kntrl.network["is_process_profile_test"]

import data.kntrl.network["is_process_profile"] as rule

test_curl_allowed_to_github {
	rule.policy with input as {"task_name": "curl", "daddr": "140.82.114.4", "domains": ["github.com"]}
		with data.process_profiles as [{"process": "curl", "allowed_hosts": ["github.com", ".amazonaws.com"], "allowed_cidrs": []}]
}

test_curl_blocked_from_npmjs {
	not rule.policy with input as {"task_name": "curl", "daddr": "104.16.0.1", "domains": ["registry.npmjs.org"]}
		with data.process_profiles as [{"process": "curl", "allowed_hosts": ["github.com", ".amazonaws.com"], "allowed_cidrs": []}]
}

test_npm_allowed_to_npmjs {
	rule.policy with input as {"task_name": "npm", "daddr": "104.16.0.1", "domains": ["registry.npmjs.org"]}
		with data.process_profiles as [{"process": "npm", "allowed_hosts": ["registry.npmjs.org"], "allowed_cidrs": []}]
}

test_npm_blocked_from_github {
	not rule.policy with input as {"task_name": "npm", "daddr": "140.82.114.4", "domains": ["github.com"]}
		with data.process_profiles as [{"process": "npm", "allowed_hosts": ["registry.npmjs.org"], "allowed_cidrs": []}]
}

test_process_profile_cidr_match {
	rule.policy with input as {"task_name": "pip", "daddr": "151.101.0.1", "domains": ["pypi.org"]}
		with data.process_profiles as [{"process": "pip", "allowed_hosts": ["pypi.org"], "allowed_cidrs": ["151.101.0.0/16"]}]
}

test_unknown_process_no_profile {
	not rule.policy with input as {"task_name": "malware", "daddr": "1.2.3.4", "domains": ["evil.com"]}
		with data.process_profiles as [{"process": "curl", "allowed_hosts": ["github.com"], "allowed_cidrs": []}]
}

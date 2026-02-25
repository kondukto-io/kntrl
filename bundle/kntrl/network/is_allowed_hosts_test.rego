package kntrl.network["is_allowed_hosts_test"]

import data.kntrl.network["is_allowed_hosts"] as rule

# test subdomain matches parent domain
test_allowed_domain {
	rule.policy with input as {"daddr":"1.1.1.1", "domains": ["foo.github.com"]}
		with data.allowed_hosts as ["github.com"]
}

test_not_allowed_domain {
	not rule.policy with input as {"daddr":"140.88.114.222", "domains": ["foo.com"]}
		with data.allowed_hosts as ["github.com"]
}

test_subdomain_boundary {
	rule.policy with input as {"daddr":"1.1.1.1", "domains": ["foo.github.com"]}
		with data.allowed_hosts as ["github.com"]
}

test_no_partial_match {
	not rule.policy with input as {"daddr":"1.1.1.1", "domains": ["evil-github.com"]}
		with data.allowed_hosts as ["github.com"]
}

test_exact_match {
	rule.policy with input as {"daddr":"1.1.1.1", "domains": ["github.com"]}
		with data.allowed_hosts as ["github.com"]
}

test_dot_prefix_pattern {
	rule.policy with input as {"daddr":"1.1.1.1", "domains": ["sub.github.com"]}
		with data.allowed_hosts as [".github.com"]
}

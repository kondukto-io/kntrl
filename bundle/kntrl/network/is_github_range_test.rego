package kntrl.network["is_github_range_test"]

import data.kntrl.network["is_github_range"] as rule

# test local ip
test_allow_github_meta {
	rule.policy with input as {"daddr":"4.148.0.12", "domains": ["foo.bar"]}
}

# test local ip
test_deny_allow_github_meta {
	not rule.policy with input as {"daddr":"1.2.3.4", "domains": ["foo.bar"]}
}

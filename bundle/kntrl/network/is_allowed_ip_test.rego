package kntrl.network["is_allowed_ip_test"]

import data.kntrl.network["is_allowed_ip"] as rule

test_allowed_ip{
	rule.policy with input as {"daddr":"140.82.114.222", "domains": ["foo.com"]}
}

test_not_allowed_ip{
	not rule.policy with input as {"daddr":"140.88.114.222", "domains": ["foo.com"]}
}

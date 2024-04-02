package kntrl.network["is_allowed_hosts_test"]

import data.kntrl.network["is_allowed_hosts"] as rule

# test local ip
test_allowed_domain{
	rule.policy with input as {"daddr":"1.1.1.1", "domains": ["foo.github.com"]}
}

test_not_allowed_domain{
	not rule.policy with input as {"daddr":"140.88.114.222", "domains": ["foo.com"]}
}

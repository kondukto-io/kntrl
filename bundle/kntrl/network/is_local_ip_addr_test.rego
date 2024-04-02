package kntrl.network["is_local_ip_addr_test"]

import data.kntrl.network["is_local_ip_addr"] as rule

# test local ip
test_allow_local_ip {
	rule.policy with input as {"daddr":"172.16.0.22", "domains": ["github.local"]}
}

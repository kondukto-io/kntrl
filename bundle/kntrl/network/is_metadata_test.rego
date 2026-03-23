package kntrl.network["is_metadata_test"]

import data.kntrl.network["is_metadata"] as rule

test_metadata_allowed_when_opted_in {
	rule.policy with input as {"daddr": "169.254.169.254", "domains": ["metadata.google.internal"]} with data.allow_metadata as true
}

test_metadata_blocked_by_default {
	not rule.policy with input as {"daddr": "169.254.169.254", "domains": ["metadata.google.internal"]} with data.allow_metadata as false
}

test_azure_metadata_allowed_when_opted_in {
	rule.policy with input as {"daddr": "168.63.129.16", "domains": ["azure.metadata"]} with data.allow_metadata as true
}

test_azure_metadata_blocked_by_default {
	not rule.policy with input as {"daddr": "168.63.129.16", "domains": ["azure.metadata"]} with data.allow_metadata as false
}

test_non_metadata_ip_not_matched {
	not rule.policy with input as {"daddr": "8.8.8.8", "domains": ["dns.google"]} with data.allow_metadata as true
}

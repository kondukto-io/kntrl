package kntrl

import rego.v1

# ══════════════════════════════════════════════════════════
# Rule 1 — Exfiltration domain blocklist
# ══════════════════════════════════════════════════════════

test_block_webhook_site_by_domain if {
	ancestry_denied with input as {
		"task_name": "node",
		"daddr": "46.4.105.116",
		"domains": ["webhook.site"],
		"ancestors": [],
	}
		with data.blocked_process_chains as []
}

test_block_pastebin_by_domain if {
	ancestry_denied with input as {
		"task_name": "curl",
		"daddr": "104.20.67.143",
		"domains": ["pastebin.com"],
		"ancestors": ["bash"],
	}
		with data.blocked_process_chains as []
}

test_block_ngrok_by_domain if {
	ancestry_denied with input as {
		"task_name": "node",
		"daddr": "1.2.3.4",
		"domains": ["abc123.ngrok-free.app"],
		"ancestors": [],
	}
		with data.blocked_process_chains as []
}

test_block_pipedream_by_sni if {
	ancestry_denied with input as {
		"task_name": "node",
		"daddr": "1.2.3.4",
		"sni": "eo123.m.pipedream.net",
		"domains": [],
		"ancestors": [],
	}
		with data.blocked_process_chains as []
}

test_allow_legitimate_domain if {
	not ancestry_denied with input as {
		"task_name": "npm",
		"daddr": "104.16.0.1",
		"domains": ["registry.npmjs.org"],
		"ancestors": ["bash"],
	}
		with data.blocked_process_chains as []
}

# ══════════════════════════════════════════════════════════
# Rule 2 — GitHub API from npm ancestry
# ══════════════════════════════════════════════════════════

test_block_github_api_from_npm_child if {
	ancestry_denied with input as {
		"task_name": "node",
		"daddr": "140.82.112.5",
		"domains": ["api.github.com"],
		"ancestors": ["npm", "bash"],
	}
		with data.blocked_process_chains as []
}

test_block_github_api_from_node_child_by_sni if {
	ancestry_denied with input as {
		"task_name": "curl",
		"daddr": "140.82.112.5",
		"sni": "api.github.com",
		"domains": [],
		"ancestors": ["node", "bash"],
	}
		with data.blocked_process_chains as []
}

test_allow_github_api_without_npm_ancestor if {
	not ancestry_denied with input as {
		"task_name": "gh",
		"daddr": "140.82.112.5",
		"domains": ["api.github.com"],
		"ancestors": ["bash"],
	}
		with data.blocked_process_chains as []
}

# ══════════════════════════════════════════════════════════
# Rule 3 — raw.githubusercontent.com from npm ancestry
# ══════════════════════════════════════════════════════════

test_block_raw_github_from_npm_child if {
	ancestry_denied with input as {
		"task_name": "node",
		"daddr": "185.199.108.133",
		"domains": ["raw.githubusercontent.com"],
		"ancestors": ["npm"],
	}
		with data.blocked_process_chains as []
}

test_allow_raw_github_without_npm_ancestor if {
	not ancestry_denied with input as {
		"task_name": "curl",
		"daddr": "185.199.108.133",
		"domains": ["raw.githubusercontent.com"],
		"ancestors": ["bash"],
	}
		with data.blocked_process_chains as []
}

# ══════════════════════════════════════════════════════════
# Rule 4 — Cloud metadata from npm ancestry
# ══════════════════════════════════════════════════════════

test_block_aws_metadata_from_npm_child if {
	ancestry_denied with input as {
		"task_name": "curl",
		"daddr": "169.254.169.254",
		"domains": [],
		"ancestors": ["npm", "bash"],
	}
		with data.blocked_process_chains as []
}

test_block_azure_metadata_from_node_child if {
	ancestry_denied with input as {
		"task_name": "wget",
		"daddr": "168.63.129.16",
		"domains": [],
		"ancestors": ["node"],
	}
		with data.blocked_process_chains as []
}

test_allow_metadata_without_npm_ancestor if {
	not ancestry_denied with input as {
		"task_name": "curl",
		"daddr": "169.254.169.254",
		"domains": [],
		"ancestors": ["bash"],
	}
		with data.blocked_process_chains as []
}

# ══════════════════════════════════════════════════════════
# Rule 5 — npm child lockdown (non-registry destinations)
# ══════════════════════════════════════════════════════════

test_block_npm_child_to_unknown_host if {
	ancestry_denied with input as {
		"task_name": "curl",
		"daddr": "93.184.216.34",
		"domains": ["example.com"],
		"ancestors": ["npm"],
	}
		with data.blocked_process_chains as []
}

test_block_npm_child_to_evil_sni if {
	ancestry_denied with input as {
		"task_name": "curl",
		"daddr": "1.2.3.4",
		"sni": "evil.com",
		"domains": [],
		"ancestors": ["node", "bash"],
	}
		with data.blocked_process_chains as []
}

test_allow_npm_child_to_registry if {
	not ancestry_denied with input as {
		"task_name": "curl",
		"daddr": "104.16.0.1",
		"domains": ["registry.npmjs.org"],
		"ancestors": ["npm"],
	}
		with data.blocked_process_chains as []
}

test_allow_npm_itself_to_any_host if {
	not ancestry_denied with input as {
		"task_name": "npm",
		"daddr": "140.82.114.4",
		"domains": ["github.com"],
		"ancestors": ["bash"],
	}
		with data.blocked_process_chains as []
}

test_allow_git_from_npm_to_github if {
	not ancestry_denied with input as {
		"task_name": "git",
		"daddr": "140.82.114.4",
		"domains": ["github.com"],
		"ancestors": ["npm"],
	}
		with data.blocked_process_chains as []
}

test_allow_node_itself_not_blocked_by_lockdown if {
	not ancestry_denied with input as {
		"task_name": "node",
		"daddr": "104.16.0.1",
		"domains": ["registry.npmjs.org"],
		"ancestors": ["npm"],
	}
		with data.blocked_process_chains as []
}

# ══════════════════════════════════════════════════════════
# Combined: YAML blocked_chains still works alongside rego
# ══════════════════════════════════════════════════════════

test_yaml_chain_curl_from_npm if {
	ancestry_denied with input as {
		"task_name": "curl",
		"daddr": "1.2.3.4",
		"domains": ["evil.com"],
		"ancestors": ["npm", "bash"],
	}
		with data.blocked_process_chains as [{"process": "curl", "ancestors": ["npm"]}]
}

test_yaml_chain_bun_from_node if {
	ancestry_denied with input as {
		"task_name": "bun",
		"daddr": "1.2.3.4",
		"domains": [],
		"ancestors": ["node"],
	}
		with data.blocked_process_chains as [{"process": "bun", "ancestors": ["node"]}]
}

package kntrl

import rego.v1

# wget to an allowed host should pass even if wget is not in allowed_processes.
# This matches BPF behavior: IPs from allowed_hosts are in the kernel allowlist
# for all processes.
test_wget_to_allowed_host_passes if {
	policy with input as {
		"task_name": "wget",
		"daddr": "52.222.201.14",
		"dport": 443,
		"domains": ["download.kondukto.io"],
		"ancestors": ["bash"],
	}
		with data.allowed_hosts as ["download.kondukto.io"]
		with data.allowed_processes as ["npm", "node", "git"]
		with data.blocked_process_chains as []
}

# wget to a host NOT in allowed_hosts should block when wget is not in allowed_processes.
test_wget_to_unknown_host_blocked if {
	not policy with input as {
		"task_name": "wget",
		"daddr": "93.184.216.34",
		"dport": 443,
		"domains": ["example.com"],
		"ancestors": ["bash"],
	}
		with data.allowed_hosts as ["download.kondukto.io"]
		with data.allowed_processes as ["npm", "node", "git"]
		with data.blocked_process_chains as []
}

# Process in allowed_processes to an allowed host should pass.
test_npm_to_allowed_host_passes if {
	policy with input as {
		"task_name": "npm",
		"daddr": "104.16.0.1",
		"dport": 443,
		"domains": ["registry.npmjs.org"],
		"ancestors": ["bash"],
	}
		with data.allowed_hosts as ["registry.npmjs.org"]
		with data.allowed_processes as ["npm", "node", "git"]
		with data.blocked_process_chains as []
}

# No allowed_processes configured — any process to allowed host should pass.
test_any_process_when_no_allowlist if {
	policy with input as {
		"task_name": "wget",
		"daddr": "52.222.201.14",
		"dport": 443,
		"domains": ["download.kondukto.io"],
		"ancestors": ["bash"],
	}
		with data.allowed_hosts as ["download.kondukto.io"]
		with data.blocked_process_chains as []
}

# CDN reverse DNS (not in allowed_hosts) from unlisted process should block.
test_cdn_reverse_dns_not_in_allowed_hosts if {
	not policy with input as {
		"task_name": "wget",
		"daddr": "52.222.201.14",
		"dport": 80,
		"domains": ["server-52-222-201-14.cdg50.r.cloudfront.net"],
		"ancestors": ["bash"],
	}
		with data.allowed_hosts as ["download.kondukto.io"]
		with data.allowed_processes as ["npm", "node", "git"]
		with data.blocked_process_chains as []
}

# Wildcard host match: wget to subdomain of allowed pattern should pass.
test_wget_to_wildcard_allowed_host if {
	policy with input as {
		"task_name": "wget",
		"daddr": "1.2.3.4",
		"dport": 443,
		"domains": ["files.download.kondukto.io"],
		"ancestors": ["bash"],
	}
		with data.allowed_hosts as [".kondukto.io"]
		with data.allowed_processes as ["npm"]
		with data.blocked_process_chains as []
}

# ancestry_denied still overrides even if host is allowed
test_ancestry_denied_overrides_allowed_host if {
	not policy with input as {
		"task_name": "curl",
		"daddr": "104.16.0.1",
		"dport": 443,
		"domains": ["registry.npmjs.org"],
		"ancestors": ["npm", "bash"],
	}
		with data.allowed_hosts as ["registry.npmjs.org"]
		with data.allowed_processes as ["npm"]
		with data.blocked_process_chains as [{"process": "curl", "ancestors": ["npm"]}]
}

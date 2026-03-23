## Shai-Hulud npm worm — advanced OPA detection rules
##
## These rules extend the built-in ancestry_denied logic with
## domain-aware, SNI-aware, and metadata-aware blocking that
## the YAML blocked_chains format cannot express.
##
## The YAML rules.yaml handles kernel-level enforcement:
##   - blocked_executables  → eBPF SIGKILL (trufflehog, nc, shred, …)
##   - blocked_chains       → simple process+ancestor deny
##   - network profiles     → per-process host allowlists
##
## This file handles policy-engine enforcement:
##   - Exfiltration domain blocklist (any process, by domain or SNI)
##   - npm child lockdown to registry-only destinations
##   - Cloud metadata access from npm ancestry
##   - GitHub API abuse from npm children
##
package kntrl

import rego.v1

# ──────────────────────────────────────────────────────────
# Rule 1 — Block known exfiltration / C2 domains
#
# Shai-Hulud exfils creds to webhook.site and similar
# paste/webhook services. Block regardless of process.
# ──────────────────────────────────────────────────────────

ancestry_denied if {
	some domain in input.domains
	_is_exfil_domain(domain)
}

# Also check TLS SNI — catches HTTPS before domain resolution
ancestry_denied if {
	input.sni != ""
	_is_exfil_domain(input.sni)
}

# ──────────────────────────────────────────────────────────
# Rule 2 — Block npm/node children from GitHub API
#
# npm install does not need api.github.com.
# The worm uses it to create exfil repos, validate stolen
# tokens, and retrieve credentials from other victims.
# ──────────────────────────────────────────────────────────

ancestry_denied if {
	_has_npm_ancestor
	some domain in input.domains
	domain == "api.github.com"
}

ancestry_denied if {
	_has_npm_ancestor
	input.sni == "api.github.com"
}

# ──────────────────────────────────────────────────────────
# Rule 3 — Block npm/node children from raw GitHub content
#
# Shai-Hulud 2.0 fetches stolen credentials from public
# repos via raw.githubusercontent.com to reuse tokens from
# other victims as a fallback exfil channel.
# ──────────────────────────────────────────────────────────

ancestry_denied if {
	_has_npm_ancestor
	some domain in input.domains
	domain == "raw.githubusercontent.com"
}

ancestry_denied if {
	_has_npm_ancestor
	input.sni == "raw.githubusercontent.com"
}

# ──────────────────────────────────────────────────────────
# Rule 4 — Block cloud metadata from npm ancestry
#
# The worm harvests instance credentials from AWS, Azure,
# and GCP metadata endpoints. This is a second layer on
# top of the YAML allow_metadata:false setting.
# ──────────────────────────────────────────────────────────

ancestry_denied if {
	_has_npm_ancestor
	_is_metadata_ip(input.daddr)
}

# ──────────────────────────────────────────────────────────
# Rule 5 — Block npm child processes from non-registry hosts
#
# If a process spawned by npm/node makes a network connection
# to anything other than the npm registry, block it.
# This catches novel exfil domains that aren't in the
# blocklist yet. Allowlist: npm itself, node, and git are
# exempt (they have their own network profiles in YAML).
# ──────────────────────────────────────────────────────────

ancestry_denied if {
	_has_npm_ancestor
	# Only apply to child tools, not npm/node/git themselves
	not input.task_name in {"npm", "node", "git"}
	count(input.domains) > 0
	not _any_domain_is_npm_registry
}

ancestry_denied if {
	_has_npm_ancestor
	not input.task_name in {"npm", "node", "git"}
	input.sni != ""
	not _is_npm_registry(input.sni)
}

# ══════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════

_has_npm_ancestor if {
	"npm" == input.ancestors[_]
}

_has_npm_ancestor if {
	"node" == input.ancestors[_]
}

# --- Exfiltration domain list ---

_is_exfil_domain(domain) if {
	# Shai-Hulud v1 exfil endpoint
	endswith(domain, "webhook.site")
}

_is_exfil_domain(domain) if {
	endswith(domain, "pipedream.net")
}

_is_exfil_domain(domain) if {
	endswith(domain, "requestbin.com")
}

_is_exfil_domain(domain) if {
	endswith(domain, "hookbin.com")
}

_is_exfil_domain(domain) if {
	endswith(domain, "beeceptor.com")
}

_is_exfil_domain(domain) if {
	endswith(domain, "requestcatcher.com")
}

_is_exfil_domain(domain) if {
	endswith(domain, "canarytokens.com")
}

_is_exfil_domain(domain) if {
	endswith(domain, "oastify.com")
}

_is_exfil_domain(domain) if {
	endswith(domain, "interact.sh")
}

_is_exfil_domain(domain) if {
	endswith(domain, "ngrok.io")
}

_is_exfil_domain(domain) if {
	endswith(domain, "ngrok-free.app")
}

_is_exfil_domain(domain) if {
	endswith(domain, "serveo.net")
}

_is_exfil_domain(domain) if {
	endswith(domain, "localhost.run")
}

_is_exfil_domain(domain) if {
	endswith(domain, "pastebin.com")
}

_is_exfil_domain(domain) if {
	endswith(domain, "paste.ee")
}

_is_exfil_domain(domain) if {
	endswith(domain, "hastebin.com")
}

_is_exfil_domain(domain) if {
	endswith(domain, "transfer.sh")
}

_is_exfil_domain(domain) if {
	endswith(domain, "file.io")
}

# --- Cloud metadata IPs ---

_is_metadata_ip(ip) if {
	# AWS / GCP instance metadata
	ip == "169.254.169.254"
}

_is_metadata_ip(ip) if {
	# Azure instance metadata
	ip == "168.63.129.16"
}

# --- npm registry check ---

_is_npm_registry(domain) if {
	endswith(domain, "npmjs.org")
}

_is_npm_registry(domain) if {
	endswith(domain, "npmjs.com")
}

_any_domain_is_npm_registry if {
	some domain in input.domains
	_is_npm_registry(domain)
}

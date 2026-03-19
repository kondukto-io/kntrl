## Supply chain protection — advanced OPA rules for GitHub Actions
##
## Extends the built-in ancestry_denied logic with domain-aware blocking
## that the YAML blocked_chains format cannot express:
##
##   - Known exfiltration/C2 domain blocklist (any process)
##   - Cloud metadata access from package manager ancestry
##   - npm/pip child processes locked to their respective registries
##
## The YAML rules.yaml handles kernel-level enforcement (blocked_executables,
## blocked_chains, network profiles). This file handles policy-engine rules
## that need domain inspection or more complex matching.
##
package kntrl

import rego.v1

# ──────────────────────────────────────────────────────────
# Rule 1 — Block known exfiltration / C2 domains
#
# Supply chain attacks commonly exfiltrate stolen credentials
# to webhook/paste/tunnel services. Block these regardless of
# which process is making the connection.
# ──────────────────────────────────────────────────────────

ancestry_denied if {
	some domain in input.domains
	_is_exfil_domain(domain)
}

# ──────────────────────────────────────────────────────────
# Rule 2 — Block cloud metadata from package manager ancestry
#
# Package install scripts should never access the cloud
# instance metadata endpoint. This catches credential theft
# from cloud-hosted runners (AWS, Azure, GCP).
# ──────────────────────────────────────────────────────────

ancestry_denied if {
	_has_pkg_manager_ancestor
	_is_metadata_ip(input.daddr)
}

# ──────────────────────────────────────────────────────────
# Rule 3 — Block npm/node children from non-registry hosts
#
# If a process spawned by npm/node makes a network connection
# to anything other than the npm registry, deny it. This
# catches novel exfil domains not in the blocklist.
# ──────────────────────────────────────────────────────────

ancestry_denied if {
	_has_npm_ancestor
	not input.task_name in {"npm", "node", "git"}
	count(input.domains) > 0
	not _any_domain_is_npm_registry
}

# ──────────────────────────────────────────────────────────
# Rule 4 — Block pip/python children from non-PyPI hosts
#
# Same logic as Rule 3, but for the Python ecosystem.
# ──────────────────────────────────────────────────────────

ancestry_denied if {
	_has_pip_ancestor
	not input.task_name in {"pip", "pip3", "python", "python3", "git"}
	count(input.domains) > 0
	not _any_domain_is_pypi
}

# ══════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════

# --- Package manager ancestor checks ---

_has_npm_ancestor if { "npm" == input.ancestors[_] }
_has_npm_ancestor if { "node" == input.ancestors[_] }

_has_pip_ancestor if { "pip" == input.ancestors[_] }
_has_pip_ancestor if { "pip3" == input.ancestors[_] }

_has_pkg_manager_ancestor if { _has_npm_ancestor }
_has_pkg_manager_ancestor if { _has_pip_ancestor }

# --- Exfiltration domain blocklist ---

_is_exfil_domain(domain) if { endswith(domain, "webhook.site") }
_is_exfil_domain(domain) if { endswith(domain, "pipedream.net") }
_is_exfil_domain(domain) if { endswith(domain, "requestbin.com") }
_is_exfil_domain(domain) if { endswith(domain, "hookbin.com") }
_is_exfil_domain(domain) if { endswith(domain, "beeceptor.com") }
_is_exfil_domain(domain) if { endswith(domain, "requestcatcher.com") }
_is_exfil_domain(domain) if { endswith(domain, "canarytokens.com") }
_is_exfil_domain(domain) if { endswith(domain, "oastify.com") }
_is_exfil_domain(domain) if { endswith(domain, "interact.sh") }
_is_exfil_domain(domain) if { endswith(domain, "ngrok.io") }
_is_exfil_domain(domain) if { endswith(domain, "ngrok-free.app") }
_is_exfil_domain(domain) if { endswith(domain, "serveo.net") }
_is_exfil_domain(domain) if { endswith(domain, "localhost.run") }
_is_exfil_domain(domain) if { endswith(domain, "pastebin.com") }
_is_exfil_domain(domain) if { endswith(domain, "transfer.sh") }
_is_exfil_domain(domain) if { endswith(domain, "file.io") }

# --- Cloud metadata IPs ---

_is_metadata_ip(ip) if { ip == "169.254.169.254" } # AWS / GCP
_is_metadata_ip(ip) if { ip == "168.63.129.16" }   # Azure

# --- Registry checks ---

_is_npm_registry(domain) if { endswith(domain, "npmjs.org") }
_is_npm_registry(domain) if { endswith(domain, "npmjs.com") }

_any_domain_is_npm_registry if {
	some domain in input.domains
	_is_npm_registry(domain)
}

_is_pypi(domain) if { endswith(domain, "pypi.org") }
_is_pypi(domain) if { endswith(domain, "pythonhosted.org") }

_any_domain_is_pypi if {
	some domain in input.domains
	_is_pypi(domain)
}

package policy

import (
	"context"
	"testing"

	"github.com/kondukto-io/kntrl/bundle"
	"github.com/open-policy-agent/opa/util"
)

// TestBlockedChains verifies ancestry chain blocking using inline OPA data
// that mirrors the YAML policy in testdata/block-chains.yaml.
//
// The policy blocks curl/wget when their process ancestry includes "sh" or "npm"+"sh".
// A local IP (192.168.1.1) is used so network_allowed always passes via
// allow_local_ip_ranges=true, isolating the ancestry logic under test.
func TestBlockedChains(t *testing.T) {
	var bundleFS = bundle.Bundle

	cases := map[string]struct {
		data     []byte
		input    []byte
		expected bool
	}{
		// ─── BLOCKED: curl spawned from sh ───
		"curl_from_sh_blocked": {
			data: []byte(`{
				"allowed_hosts": [".github.com"],
				"allow_local_ip_ranges": true,
				"allow_github_meta": false,
				"blocked_process_chains": [
					{"process": "curl", "ancestors": ["sh"]}
				]
			}`),
			input: []byte(`{
				"pid": 1234,
				"task_name": "curl",
				"proto": "tcp",
				"daddr": "192.168.1.1",
				"dport": 443,
				"domains": ["github.com"],
				"ancestors": ["sh", "bash"]
			}`),
			expected: false,
		},

		// ─── BLOCKED: wget spawned from sh ───
		"wget_from_sh_blocked": {
			data: []byte(`{
				"allowed_hosts": [".github.com"],
				"allow_local_ip_ranges": true,
				"allow_github_meta": false,
				"blocked_process_chains": [
					{"process": "wget", "ancestors": ["sh"]}
				]
			}`),
			input: []byte(`{
				"pid": 1235,
				"task_name": "wget",
				"proto": "tcp",
				"daddr": "192.168.1.1",
				"dport": 443,
				"domains": ["github.com"],
				"ancestors": ["sh", "node"]
			}`),
			expected: false,
		},

		// ─── BLOCKED: curl from npm -> sh -> curl chain ───
		"curl_from_npm_sh_blocked": {
			data: []byte(`{
				"allowed_hosts": [".github.com"],
				"allow_local_ip_ranges": true,
				"allow_github_meta": false,
				"blocked_process_chains": [
					{"process": "curl", "ancestors": ["npm", "sh"]}
				]
			}`),
			input: []byte(`{
				"pid": 1236,
				"task_name": "curl",
				"proto": "tcp",
				"daddr": "192.168.1.1",
				"dport": 443,
				"domains": ["github.com"],
				"ancestors": ["sh", "npm", "node", "bash"]
			}`),
			expected: false,
		},

		// ─── BLOCKED: wget from npm -> sh -> wget chain ───
		"wget_from_npm_sh_blocked": {
			data: []byte(`{
				"allowed_hosts": [".github.com"],
				"allow_local_ip_ranges": true,
				"allow_github_meta": false,
				"blocked_process_chains": [
					{"process": "wget", "ancestors": ["npm", "sh"]}
				]
			}`),
			input: []byte(`{
				"pid": 1237,
				"task_name": "wget",
				"proto": "tcp",
				"daddr": "192.168.1.1",
				"dport": 443,
				"domains": ["github.com"],
				"ancestors": ["sh", "npm", "bash"]
			}`),
			expected: false,
		},

		// ─── ALLOWED: curl run directly by user (no sh in ancestry) ───
		"curl_direct_allowed": {
			data: []byte(`{
				"allowed_hosts": [".github.com"],
				"allow_local_ip_ranges": true,
				"allow_github_meta": false,
				"blocked_process_chains": [
					{"process": "curl", "ancestors": ["sh"]}
				]
			}`),
			input: []byte(`{
				"pid": 1238,
				"task_name": "curl",
				"proto": "tcp",
				"daddr": "192.168.1.1",
				"dport": 443,
				"domains": ["github.com"],
				"ancestors": ["bash"]
			}`),
			expected: true,
		},

		// ─── ALLOWED: wget run directly (no sh in ancestry) ───
		"wget_direct_allowed": {
			data: []byte(`{
				"allowed_hosts": [".github.com"],
				"allow_local_ip_ranges": true,
				"allow_github_meta": false,
				"blocked_process_chains": [
					{"process": "wget", "ancestors": ["sh"]}
				]
			}`),
			input: []byte(`{
				"pid": 1239,
				"task_name": "wget",
				"proto": "tcp",
				"daddr": "192.168.1.1",
				"dport": 443,
				"domains": ["github.com"],
				"ancestors": ["bash"]
			}`),
			expected: true,
		},

		// ─── ALLOWED: npm itself is not blocked (only curl/wget from npm) ───
		"npm_itself_allowed": {
			data: []byte(`{
				"allowed_hosts": ["registry.npmjs.org"],
				"allow_local_ip_ranges": true,
				"allow_github_meta": false,
				"blocked_process_chains": [
					{"process": "curl", "ancestors": ["npm", "sh"]}
				]
			}`),
			input: []byte(`{
				"pid": 1240,
				"task_name": "npm",
				"proto": "tcp",
				"daddr": "192.168.1.1",
				"dport": 443,
				"domains": ["registry.npmjs.org"],
				"ancestors": ["bash"]
			}`),
			expected: true,
		},

		// ─── ALLOWED: curl from npm but without sh (partial match) ───
		"curl_from_npm_without_sh_allowed": {
			data: []byte(`{
				"allowed_hosts": [".github.com"],
				"allow_local_ip_ranges": true,
				"allow_github_meta": false,
				"blocked_process_chains": [
					{"process": "curl", "ancestors": ["npm", "sh"]}
				]
			}`),
			input: []byte(`{
				"pid": 1241,
				"task_name": "curl",
				"proto": "tcp",
				"daddr": "192.168.1.1",
				"dport": 443,
				"domains": ["github.com"],
				"ancestors": ["npm", "node", "bash"]
			}`),
			expected: true,
		},

		// ─── ALLOWED: git is not in blocked list ───
		"git_from_sh_allowed": {
			data: []byte(`{
				"allowed_hosts": [".github.com"],
				"allow_local_ip_ranges": true,
				"allow_github_meta": false,
				"blocked_process_chains": [
					{"process": "curl", "ancestors": ["sh"]},
					{"process": "wget", "ancestors": ["sh"]}
				]
			}`),
			input: []byte(`{
				"pid": 1242,
				"task_name": "git",
				"proto": "tcp",
				"daddr": "192.168.1.1",
				"dport": 443,
				"domains": ["github.com"],
				"ancestors": ["sh", "npm", "bash"]
			}`),
			expected: true,
		},

		// ─── ALLOWED: no blocked chains configured ───
		"no_chains_configured": {
			data: []byte(`{
				"allowed_hosts": [".github.com"],
				"allow_local_ip_ranges": true,
				"allow_github_meta": false
			}`),
			input: []byte(`{
				"pid": 1243,
				"task_name": "curl",
				"proto": "tcp",
				"daddr": "192.168.1.1",
				"dport": 443,
				"domains": ["github.com"],
				"ancestors": ["sh", "npm", "bash"]
			}`),
			expected: true,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := New(bundleFS, tc.data)
			if err != nil {
				t.Fatalf("policy init: %v", err)
			}
			p.AddQuery("data.kntrl.policy")

			var input map[string]interface{}
			if err := util.Unmarshal(tc.input, &input); err != nil {
				t.Fatalf("unmarshal input: %v", err)
			}

			result, err := p.Eval(context.Background(), input)
			if err != nil {
				t.Fatalf("eval: %v", err)
			}

			if result != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, result)
			}
		})
	}
}

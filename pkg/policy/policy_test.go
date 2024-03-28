package policy

import (
	"context"
	"testing"

	"github.com/kondukto-io/kntrl/bundle"
)

var testCases = map[string]struct {
	query    []byte
	input    []byte
	expected bool
}{
	"allow_local_ip_ranges": {
		[]byte(`{"allowed_hosts":["foo.com"], "allowed_ip_addr":["1.1.1.1"], "allow_github_meta": false, "allow_local_ip_ranges": true}`),
		[]byte(`{"pid": 2806,"task_name": "curl","proto": "tcp","daddr": "192.168.0.1","dport": 443,"domains": [".kondukto.io"]}`),
		true,
	},
	"allow_ip_addr": {
		[]byte(`{"allowed_hosts":["foo.com"], "allowed_ip_addr":["1.1.1.1"], "allow_github_meta": false, "allow_local_ip_ranges": true}`),
		[]byte(`{"pid": 2806,"task_name": "curl","proto": "tcp","daddr": "1.1.1.1","dport": 443,"domains": [".kondukto.io"]}`),
		true,
	},
	"allow_host": {
		[]byte(`{"allowed_hosts":["foo.com"], "allowed_ip_addr":["1.1.1.1"], "allow_github_meta": false, "allow_local_ip_ranges": true}`),
		[]byte(`{"pid": 2806,"task_name": "curl","proto": "tcp","daddr": "1.1.1.1","dport": 443,"domains": ["foo.com"]}`),
		true,
	},
}

func TestPolicyRawLocal(t *testing.T) {
	var bundleFS = bundle.Bundle

	for name, test := range testCases {
		p, err := New(bundleFS, test.query)
		if err != nil {
			t.Errorf("[%s] policy init error: %v", name, err)
		}
		p.AddQuery("data.kntrl.policy")

		result, err := p.Eval(context.Background(), test.input)
		if err != nil {
			t.Errorf("[%s] eval error: %v", name, err)
		}

		if result != test.expected {
			t.Errorf("[%s] expected policy status '%v', got %v", name, test.expected, result)
		}

	}
}

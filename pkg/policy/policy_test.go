package policy

import (
	"context"
	"testing"

	"github.com/kondukto-io/kntrl/bundle"
)

func TestPolicyRawLocal(t *testing.T) {
	var bundleFS = bundle.Bundle

	raw := `{"allowed_hosts":["foo.com"], "allowed_ip_addr":["1.1.1.1"], "allow_github_meta": false, "allow_local_ip_ranges": true}`

	input := `{
    "pid": 2806,
    "task_name": "curl",
    "proto": "tcp",
    "daddr": "192.168.0.1",
    "dport": 443,
    "domains": [
        ".kondukto.io"
    ]}`

	p, err := New(bundleFS, []byte(raw))
	if err != nil {
		t.Errorf("policy init error: %v", err)
	}

	p.AddQuery("data.kntrl.policy")

	result, err := p.Eval(context.Background(), []byte(input))
	if err != nil {
		t.Errorf("eval error: %v", err)
	}

	expected := true
	if result != expected {
		t.Errorf("expected policy status to be '%v', got %v", expected, result)
	}
}

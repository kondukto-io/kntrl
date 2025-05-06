package policy

import (
	"context"
	"testing"

	"github.com/kondukto-io/kntrl/bundle"
	"github.com/open-policy-agent/opa/util"
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
	"disallow_local_ip_ranges": {
		[]byte(`{"allowed_hosts":["foo.com"], "allowed_ip_addr":["1.1.1.1"], "allow_github_meta": false, "allow_local_ip_ranges": false}`),
		[]byte(`{"pid": 2806,"task_name": "curl","proto": "tcp","daddr": "192.168.0.1","dport": 443,"domains": [".kondukto.io"]}`),
		false,
	},
	"allow_ip_addr": {
		[]byte(`{"allowed_hosts":["foo.com"], "allowed_ip_addr":["1.1.1.1"], "allow_github_meta": false, "allow_local_ip_ranges": true}`),
		[]byte(`{"pid": 2806,"task_name": "curl","proto": "tcp","daddr": "1.1.1.1","dport": 443,"domains": [".kondukto.io"]}`),
		true,
	},
	"allow_host": {
		[]byte(`{"allowed_hosts":["foo.com"], "allowed_ip_addr":["1.2.3.1"], "allow_github_meta": false, "allow_local_ip_ranges": true}`),
		[]byte(`{"pid": 2806,"task_name": "curl","proto": "tcp","daddr": "1.1.1.1","dport": 443,"domains": ["foo.com"]}`),
		true,
	},
	"allow_github_meta": {
		[]byte(`{"allowed_hosts":["foo.com"], "allowed_ip_addr":["1.1.1.1"], "allow_github_meta": true, "allow_local_ip_ranges": false}`),
		[]byte(`{"daddr":"4.148.0.12", "domains": ["foo.bar"]}`),
		true,
	},
	"allow_github_meta_1": {
		[]byte(`{"allowed_hosts":["foo.com"], "allowed_ip_addr":["1.1.1.1"], "allow_github_meta": true, "allow_local_ip_ranges": false}`),
		[]byte(`{"pid":1636,"task_name":".NET ThreadPool","proto":"tcp","daddr":"20.102.39.57","dport":443,"domains":["."]}`),
		true,
	},
	"disallow_github_meta": {
		[]byte(`{"allowed_hosts":["foo.com"], "allowed_ip_addr":["1.1.1.1"], "allow_github_meta": false, "allow_local_ip_ranges": false}`),
		[]byte(`{"pid":1636,"task_name":".NET ThreadPool","proto":"tcp","daddr":"20.102.39.57","dport":443,"domains":["."]}`),
		false,
	},
	"allow_github_meta_2": {
		[]byte(`{"allowed_hosts":["foo.com"], "allowed_ip_addr":["1.1.1.1"], "allow_github_meta": false, "allow_local_ip_ranges": false}`),
		[]byte(`{"pid":1798,"task_name":".NET TP Worker","proto":"tcp","daddr":"140.82.113.22","dport":443,"domains":["lb-140-82-113-22-iad.github.com"]}`),
		true,
	},
}

func TestPolicyRaw(t *testing.T) {
	var bundleFS = bundle.Bundle

	for name, test := range testCases {
		p, err := New(bundleFS, test.query)
		if err != nil {
			t.Errorf("[%s] policy init error: %v", name, err)
		}
		p.AddQuery("data.kntrl.policy")

		var inputjson map[string]interface{}
		if err := util.Unmarshal(test.input, &inputjson); err != nil {
			t.Errorf("[%s] unmarshal error: %v", name, err)
		}

		result, err := p.Eval(context.Background(), inputjson)
		if err != nil {
			t.Errorf("[%s] eval error: %v", name, err)
		}

		if result != test.expected {
			t.Errorf("[%s] expected policy status '%v', got %v", name, test.expected, result)
		}
	}
}

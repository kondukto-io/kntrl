package policy

import (
	"context"
	"testing"

	"github.com/kondukto-io/kntrl/bundle"
	"github.com/kondukto-io/kntrl/internal/core/domain"
)

func TestNetworkProcessRestrictions(t *testing.T) {
	p, err := New(bundle.Bundle, []byte(`{
		"allowed_hosts":["github.com","registry.npmjs.org"],
		"allowed_ip_addr":["140.82.114.3"],
		"allowed_processes":["node","git"],
		"process_profiles":[{"process":"node","allowed_hosts":["registry.npmjs.org"]}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	p.AddQuery("data.kntrl.policy")
	for _, tc := range []struct {
		process, host string
		want          bool
	}{
		{"git", "github.com", true},
		{"node", "github.com", false},
		{"node", "registry.npmjs.org", true},
		{"wget", "github.com", false},
	} {
		t.Run(tc.process+"/"+tc.host, func(t *testing.T) {
			got, err := p.EvalEvent(context.Background(), domain.ReportEvent{TaskName: tc.process, DestinationAddress: "140.82.114.3", DestinationPort: 443, Domains: []string{tc.host}})
			if err != nil || got != tc.want {
				t.Fatalf("got %v, want %v, err=%v", got, tc.want, err)
			}
		})
	}
}

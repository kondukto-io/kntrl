package config

import (
	"net"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDNSDefaultsAndOverrides(t *testing.T) {
	for _, tc := range []struct {
		name, yaml string
		want       []string
	}{
		{"default", "{}", []string{"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888", "2001:4860:4860::8844"}},
		{"private", "rules:\n  dns:\n    allowed_servers: [10.0.0.53, 'fd00::53']", []string{"10.0.0.53", "fd00::53"}},
		{"disabled", "rules:\n  dns:\n    allowed_servers: []", []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cfg PolicyConfig
			if err := yaml.Unmarshal([]byte(tc.yaml), &cfg); err != nil {
				t.Fatal(err)
			}
			merged := Merge(&PolicyConfig{}, &cfg)
			if got := dnsServers(merged.Rules.DNS); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			_, data, err := ToOPAData(merged)
			if err != nil {
				t.Fatal(err)
			}
			if len(data.AllowedDNSServers) != len(tc.want) {
				t.Fatalf("wrong resolver count: %v", data.AllowedDNSServers)
			}
			for i, ip := range data.AllowedDNSServers {
				if !ip.Equal(net.ParseIP(tc.want[i])) {
					t.Errorf("resolver %d: %s", i, ip)
				}
				for _, allowed := range data.AllowedIPs {
					if ip.Equal(allowed) {
						t.Errorf("DNS resolver %s received general IP permission", ip)
					}
				}
			}
		})
	}
}

func TestDNSListReplacesInheritedResolvers(t *testing.T) {
	base := &PolicyConfig{Rules: RulesConfig{DNS: DNSRules{AllowedServers: []string{"8.8.8.8"}}}}
	override := &PolicyConfig{Rules: RulesConfig{DNS: DNSRules{AllowedServers: []string{"10.0.0.53"}}}}
	if got := Merge(base, override).Rules.DNS.AllowedServers; !reflect.DeepEqual(got, override.Rules.DNS.AllowedServers) {
		t.Fatal(got)
	}
}

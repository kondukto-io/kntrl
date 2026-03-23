package utils

import "testing"

func TestMatchesMonitoredPath(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		paths    []string
		want     bool
		wantRule string
	}{
		// Exact match
		{
			name:     "exact match /etc/shadow",
			filename: "/etc/shadow",
			paths:    []string{"/etc/shadow"},
			want:     true,
			wantRule: "/etc/shadow",
		},

		// Prefix match (directory)
		{
			name:     "prefix match /root/.ssh/",
			filename: "/root/.ssh/id_rsa",
			paths:    []string{"/root/.ssh/"},
			want:     true,
			wantRule: "/root/.ssh/",
		},
		{
			name:     "prefix match /var/run/secrets/",
			filename: "/var/run/secrets/kubernetes.io/serviceaccount/token",
			paths:    []string{"/var/run/secrets/"},
			want:     true,
			wantRule: "/var/run/secrets/",
		},

		// Suffix match (home-relative file)
		{
			name:     "suffix match /.npmrc under home",
			filename: "/home/user/.npmrc",
			paths:    []string{"/.npmrc"},
			want:     true,
			wantRule: "/.npmrc",
		},
		{
			name:     "suffix match /.npmrc under root",
			filename: "/root/.npmrc",
			paths:    []string{"/.npmrc"},
			want:     true,
			wantRule: "/.npmrc",
		},
		{
			name:     "suffix match /.kube/config",
			filename: "/home/dev/.kube/config",
			paths:    []string{"/.kube/config"},
			want:     true,
			wantRule: "/.kube/config",
		},

		// Contains match (home-relative directory)
		{
			name:     "contains match /.ssh/ under home",
			filename: "/home/user/.ssh/id_ed25519",
			paths:    []string{"/.ssh/"},
			want:     true,
			wantRule: "/.ssh/",
		},
		{
			name:     "contains match /.aws/ under home",
			filename: "/home/user/.aws/credentials",
			paths:    []string{"/.aws/"},
			want:     true,
			wantRule: "/.aws/",
		},
		{
			name:     "contains match /.config/gh/",
			filename: "/home/user/.config/gh/hosts.yml",
			paths:    []string{"/.config/gh/"},
			want:     true,
			wantRule: "/.config/gh/",
		},

		// No match
		{
			name:     "no match different file",
			filename: "/home/user/.bashrc",
			paths:    []string{"/.npmrc", "/.ssh/", "/etc/shadow"},
			want:     false,
			wantRule: "",
		},
		{
			name:     "no match partial name",
			filename: "/home/user/.npmrc-backup",
			paths:    []string{"/.npmrc"},
			want:     false,
			wantRule: "",
		},

		// Multiple rules, first match wins
		{
			name:     "multiple rules first match",
			filename: "/home/user/.ssh/id_rsa",
			paths:    []string{"/.npmrc", "/.ssh/", "/etc/shadow"},
			want:     true,
			wantRule: "/.ssh/",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, gotRule := MatchesMonitoredPath(tc.filename, tc.paths)
			if got != tc.want {
				t.Errorf("MatchesMonitoredPath(%q) = %v, want %v", tc.filename, got, tc.want)
			}
			if gotRule != tc.wantRule {
				t.Errorf("MatchesMonitoredPath(%q) rule = %q, want %q", tc.filename, gotRule, tc.wantRule)
			}
		})
	}
}

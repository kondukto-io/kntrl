package ci

import (
	"os"
	"testing"
)

func TestDetect_NoCI(t *testing.T) {
	// Ensure no CI env vars are set
	os.Unsetenv("GITHUB_ACTIONS")
	os.Unsetenv("GITLAB_CI")
	os.Unsetenv("JENKINS_URL")

	m := Detect()
	if m != nil {
		t.Errorf("expected nil metadata when no CI env is set, got %+v", m)
	}
}

func TestDetect_GitHubActions(t *testing.T) {
	// Set GitHub Actions env vars
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_REPOSITORY", "owner/repo")
	t.Setenv("GITHUB_REF_NAME", "main")
	t.Setenv("GITHUB_SHA", "abc123def456")
	t.Setenv("GITHUB_RUN_ID", "12345678")
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")
	t.Setenv("GITHUB_ACTOR", "developer")
	t.Setenv("GITHUB_EVENT_NAME", "pull_request")

	m := Detect()
	if m == nil {
		t.Fatal("expected metadata, got nil")
	}

	if m.Provider != "github_actions" {
		t.Errorf("provider = %q, want %q", m.Provider, "github_actions")
	}
	if m.Repository != "owner/repo" {
		t.Errorf("repository = %q, want %q", m.Repository, "owner/repo")
	}
	if m.Branch != "main" {
		t.Errorf("branch = %q, want %q", m.Branch, "main")
	}
	if m.CommitSHA != "abc123def456" {
		t.Errorf("commit_sha = %q, want %q", m.CommitSHA, "abc123def456")
	}
	if m.RunID != "12345678" {
		t.Errorf("run_id = %q, want %q", m.RunID, "12345678")
	}
	if m.RunURL != "https://github.com/owner/repo/actions/runs/12345678" {
		t.Errorf("run_url = %q, want %q", m.RunURL, "https://github.com/owner/repo/actions/runs/12345678")
	}
	if m.Actor != "developer" {
		t.Errorf("actor = %q, want %q", m.Actor, "developer")
	}
	if m.EventName != "pull_request" {
		t.Errorf("event_name = %q, want %q", m.EventName, "pull_request")
	}
}

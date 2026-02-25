package ci

import "os"

type githubActions struct{}

func init() { Register(&githubActions{}) }

func (g *githubActions) Name() string { return "github_actions" }

func (g *githubActions) Detect() bool {
	return os.Getenv("GITHUB_ACTIONS") == "true"
}

func (g *githubActions) GetMetadata() Metadata {
	repo := os.Getenv("GITHUB_REPOSITORY")
	runID := os.Getenv("GITHUB_RUN_ID")
	serverURL := os.Getenv("GITHUB_SERVER_URL")

	var runURL string
	if serverURL != "" && repo != "" && runID != "" {
		runURL = serverURL + "/" + repo + "/actions/runs/" + runID
	}

	return Metadata{
		Provider:   "github_actions",
		Repository: repo,
		Branch:     os.Getenv("GITHUB_REF_NAME"),
		CommitSHA:  os.Getenv("GITHUB_SHA"),
		RunID:      runID,
		RunURL:     runURL,
		Actor:      os.Getenv("GITHUB_ACTOR"),
		EventName:  os.Getenv("GITHUB_EVENT_NAME"),
	}
}

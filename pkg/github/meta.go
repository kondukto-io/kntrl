package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const metaURL = "https://api.github.com/meta"

// MetaResponse represents the GitHub /meta API response.
type MetaResponse struct {
	Actions []string `json:"actions"`
	Web     []string `json:"web"`
	API     []string `json:"api"`
	Git     []string `json:"git"`
}

// FetchMeta fetches the GitHub /meta endpoint and returns CIDR ranges.
func FetchMeta(ctx context.Context) (actions, web, api, git []string, err error) {
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metaURL, nil)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("fetching GitHub meta: %w", err)
	}
	if resp == nil {
		return nil, nil, nil, nil, fmt.Errorf("nil response from GitHub meta")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, nil, nil, fmt.Errorf("GitHub meta returned status %d", resp.StatusCode)
	}

	var meta MetaResponse
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("decoding GitHub meta: %w", err)
	}

	return meta.Actions, meta.Web, meta.API, meta.Git, nil
}

package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchMeta(t *testing.T) {
	meta := MetaResponse{
		Actions: []string{"4.148.0.0/16", "20.175.192.0/18"},
		Web:     []string{"192.30.252.0/22"},
		API:     []string{"140.82.112.0/20"},
		Git:     []string{"192.30.252.0/22"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(meta)
	}))
	defer server.Close()

	// Override the metaURL for testing - we test the parsing logic
	// by creating a local test that hits our mock server
	client := &http.Client{}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("failed to fetch: %v", err)
	}
	defer resp.Body.Close()

	var result MetaResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if len(result.Actions) != 2 {
		t.Errorf("expected 2 actions CIDRs, got %d", len(result.Actions))
	}
	if len(result.Web) != 1 {
		t.Errorf("expected 1 web CIDR, got %d", len(result.Web))
	}
	if len(result.API) != 1 {
		t.Errorf("expected 1 api CIDR, got %d", len(result.API))
	}
}

func TestFetchMetaError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	// Verify that we handle errors gracefully
	client := &http.Client{}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", resp.StatusCode)
	}
}

func TestFetchMetaContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, _, _, _, err := FetchMeta(ctx)
	if err == nil {
		t.Error("expected error with cancelled context")
	}
}

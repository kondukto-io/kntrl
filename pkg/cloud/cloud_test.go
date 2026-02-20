package cloud

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/kondukto-io/kntrl/internal/core/domain"
	"github.com/kondukto-io/kntrl/pkg/ci"
)

// startTestNATSServer spins up an in-process NATS server on a random port.
func startTestNATSServer(t *testing.T) *server.Server {
	t.Helper()
	opts := &server.Options{
		Host: "127.0.0.1",
		Port: -1, // random port
	}
	ns, err := server.NewServer(opts)
	if err != nil {
		t.Fatalf("failed to create test NATS server: %v", err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS server not ready")
	}
	t.Cleanup(func() { ns.Shutdown() })
	return ns
}

func TestClient_SendAndDispatch(t *testing.T) {
	received := make(chan EventPayload, 10)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("authorization header = %q, want %q", r.Header.Get("Authorization"), "Bearer test-key")
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content-type = %q, want %q", r.Header.Get("Content-Type"), "application/json")
		}
		if r.Header.Get("User-Agent") != "kntrl-agent/1.0" {
			t.Errorf("user-agent = %q, want %q", r.Header.Get("User-Agent"), "kntrl-agent/1.0")
		}

		var evt EventPayload
		if err := json.NewDecoder(r.Body).Decode(&evt); err != nil {
			t.Errorf("failed to decode event: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		received <- evt
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ciMeta := &ci.Metadata{Provider: "github_actions", Repository: "owner/repo"}
	client := New(Config{APIURL: srv.URL, APIKey: "test-key"}, ciMeta, "test-session")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client.Start(ctx)

	client.Send("network", 1708281600, map[string]string{"dst": "1.2.3.4"})

	select {
	case evt := <-received:
		if evt.SessionID != "test-session" {
			t.Errorf("session_id = %q, want %q", evt.SessionID, "test-session")
		}
		if evt.EventType != "network" {
			t.Errorf("event_type = %q, want %q", evt.EventType, "network")
		}
		if evt.CI == nil || evt.CI.Provider != "github_actions" {
			t.Errorf("ci metadata missing or wrong provider")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestClient_SendSummary(t *testing.T) {
	var receivedSummary SummaryPayload

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/api/v1/sessions/summary" {
			t.Errorf("path = %q, want %q", r.URL.Path, "/api/v1/sessions/summary")
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("authorization header = %q, want %q", r.Header.Get("Authorization"), "Bearer test-key")
		}

		if err := json.NewDecoder(r.Body).Decode(&receivedSummary); err != nil {
			t.Errorf("failed to decode summary: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := New(Config{APIURL: srv.URL, APIKey: "test-key"}, nil, "summary-session")

	// Start to trigger auth fallback (sets up HTTP path)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client.Start(ctx)

	summary := SummaryPayload{
		Mode: "trace",
		NetworkEvents: []domain.ReportEvent{
			{ProcessID: 1, TaskName: "curl", Policy: "pass"},
		},
		Counts: domain.SummaryCounts{
			TotalNetwork: 1,
			Passed:       1,
		},
	}

	if err := client.SendSummary(summary); err != nil {
		t.Fatalf("SendSummary failed: %v", err)
	}

	if receivedSummary.SessionID != "summary-session" {
		t.Errorf("session_id = %q, want %q", receivedSummary.SessionID, "summary-session")
	}
	if receivedSummary.Mode != "trace" {
		t.Errorf("mode = %q, want %q", receivedSummary.Mode, "trace")
	}
	if receivedSummary.Counts.TotalNetwork != 1 {
		t.Errorf("counts.total_network = %d, want %d", receivedSummary.Counts.TotalNetwork, 1)
	}
	if receivedSummary.StartedAt == 0 {
		t.Error("started_at should be non-zero")
	}
	if receivedSummary.FinishedAt == 0 {
		t.Error("finished_at should be non-zero")
	}
}

func TestClient_NATSPublish(t *testing.T) {
	ns := startTestNATSServer(t)
	natsURL := ns.ClientURL()

	// Subscribe to events before publishing
	sub, err := nats.Connect(natsURL)
	if err != nil {
		t.Fatalf("subscriber connect: %v", err)
	}
	defer sub.Close()

	received := make(chan *nats.Msg, 10)
	if _, err := sub.Subscribe("kntrl.events.test-session.>", func(msg *nats.Msg) {
		received <- msg
	}); err != nil {
		t.Fatalf("subscribe error: %v", err)
	}
	if err := sub.Flush(); err != nil {
		t.Fatalf("flush error: %v", err)
	}

	// Mock auth endpoint
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth" {
			json.NewEncoder(w).Encode(authResponse{
				NatsURL:   natsURL,
				NatsToken: "",
				SessionID: "test-session",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	ciMeta := &ci.Metadata{Provider: "github_actions", Repository: "owner/repo"}
	client := New(Config{APIURL: srv.URL, APIKey: "test-key"}, ciMeta, "initial-session")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client.Start(ctx)

	// Verify NATS was connected
	if client.nc == nil {
		t.Fatal("expected NATS connection, got nil (HTTP fallback)")
	}

	client.Send("network", 1708281600, map[string]string{"dst": "1.2.3.4"})

	select {
	case msg := <-received:
		if msg.Subject != "kntrl.events.test-session.network" {
			t.Errorf("subject = %q, want %q", msg.Subject, "kntrl.events.test-session.network")
		}
		var evt EventPayload
		if err := json.Unmarshal(msg.Data, &evt); err != nil {
			t.Fatalf("unmarshal error: %v", err)
		}
		if evt.SessionID != "test-session" {
			t.Errorf("session_id = %q, want %q", evt.SessionID, "test-session")
		}
		if evt.EventType != "network" {
			t.Errorf("event_type = %q, want %q", evt.EventType, "network")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for NATS event")
	}

	client.Close()
}

func TestClient_NATSSummary(t *testing.T) {
	ns := startTestNATSServer(t)
	natsURL := ns.ClientURL()

	// Subscribe to summary subject before publishing
	sub, err := nats.Connect(natsURL)
	if err != nil {
		t.Fatalf("subscriber connect: %v", err)
	}
	defer sub.Close()

	received := make(chan *nats.Msg, 10)
	if _, err := sub.Subscribe("kntrl.sessions.test-session.summary", func(msg *nats.Msg) {
		received <- msg
	}); err != nil {
		t.Fatalf("subscribe error: %v", err)
	}
	if err := sub.Flush(); err != nil {
		t.Fatalf("flush error: %v", err)
	}

	// Mock auth endpoint
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth" {
			json.NewEncoder(w).Encode(authResponse{
				NatsURL:   natsURL,
				NatsToken: "",
				SessionID: "test-session",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := New(Config{APIURL: srv.URL, APIKey: "test-key"}, nil, "initial-session")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client.Start(ctx)

	if client.nc == nil {
		t.Fatal("expected NATS connection")
	}

	summary := SummaryPayload{
		Mode: "trace",
		Counts: domain.SummaryCounts{
			TotalNetwork: 5,
			Passed:       3,
		},
	}

	if err := client.SendSummary(summary); err != nil {
		t.Fatalf("SendSummary failed: %v", err)
	}

	select {
	case msg := <-received:
		if msg.Subject != "kntrl.sessions.test-session.summary" {
			t.Errorf("subject = %q, want %q", msg.Subject, "kntrl.sessions.test-session.summary")
		}
		var s SummaryPayload
		if err := json.Unmarshal(msg.Data, &s); err != nil {
			t.Fatalf("unmarshal error: %v", err)
		}
		if s.SessionID != "test-session" {
			t.Errorf("session_id = %q, want %q", s.SessionID, "test-session")
		}
		if s.StartedAt == 0 {
			t.Error("started_at should be non-zero")
		}
		if s.FinishedAt == 0 {
			t.Error("finished_at should be non-zero")
		}
		if s.Counts.TotalNetwork != 5 {
			t.Errorf("counts.total_network = %d, want %d", s.Counts.TotalNetwork, 5)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for NATS summary")
	}

	client.Close()
}

func TestClient_AuthFailure_FallbackHTTP(t *testing.T) {
	received := make(chan EventPayload, 10)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/api/v1/events" {
			var evt EventPayload
			if err := json.NewDecoder(r.Body).Decode(&evt); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			received <- evt
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := New(Config{APIURL: srv.URL, APIKey: "test-key"}, nil, "fallback-session")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client.Start(ctx)

	// Verify it fell back to HTTP (no NATS connection)
	if client.nc != nil {
		t.Fatal("expected nil NATS connection on auth failure")
	}

	client.Send("network", 1708281600, map[string]string{"dst": "1.2.3.4"})

	select {
	case evt := <-received:
		if evt.SessionID != "fallback-session" {
			t.Errorf("session_id = %q, want %q", evt.SessionID, "fallback-session")
		}
		if evt.EventType != "network" {
			t.Errorf("event_type = %q, want %q", evt.EventType, "network")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for HTTP fallback event")
	}
}

func TestClient_SubjectNaming(t *testing.T) {
	ns := startTestNATSServer(t)
	natsURL := ns.ClientURL()

	// Subscribe to all subjects
	sub, err := nats.Connect(natsURL)
	if err != nil {
		t.Fatalf("subscriber connect: %v", err)
	}
	defer sub.Close()

	received := make(chan *nats.Msg, 20)
	if _, err := sub.Subscribe("kntrl.>", func(msg *nats.Msg) {
		received <- msg
	}); err != nil {
		t.Fatalf("subscribe error: %v", err)
	}
	if err := sub.Flush(); err != nil {
		t.Fatalf("flush error: %v", err)
	}

	// Mock auth endpoint
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth" {
			json.NewEncoder(w).Encode(authResponse{
				NatsURL:   natsURL,
				NatsToken: "",
				SessionID: "sess123",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := New(Config{APIURL: srv.URL, APIKey: "test-key"}, nil, "initial")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client.Start(ctx)

	if client.nc == nil {
		t.Fatal("expected NATS connection")
	}

	tests := []struct {
		eventType       string
		expectedSubject string
	}{
		{"network", "kntrl.events.sess123.network"},
		{"process", "kntrl.events.sess123.process"},
		{"dns", "kntrl.events.sess123.dns"},
		{"file", "kntrl.events.sess123.file"},
	}

	for _, tt := range tests {
		client.Send(tt.eventType, 1708281600, map[string]string{"test": "data"})
	}

	subjects := make(map[string]bool)
	for i := 0; i < len(tests); i++ {
		select {
		case msg := <-received:
			subjects[msg.Subject] = true
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for event %d", i)
		}
	}

	for _, tt := range tests {
		if !subjects[tt.expectedSubject] {
			t.Errorf("missing subject %q for event type %q", tt.expectedSubject, tt.eventType)
		}
	}

	// Verify summary subject
	if err := client.SendSummary(SummaryPayload{Mode: "trace"}); err != nil {
		t.Fatalf("SendSummary failed: %v", err)
	}

	select {
	case msg := <-received:
		if msg.Subject != "kntrl.sessions.sess123.summary" {
			t.Errorf("summary subject = %q, want %q", msg.Subject, "kntrl.sessions.sess123.summary")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for summary")
	}

	client.Close()
}

package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestWebhookSend(t *testing.T) {
	var mu sync.Mutex
	var received []Event

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var evt Event
		if err := json.NewDecoder(r.Body).Decode(&evt); err != nil {
			t.Errorf("failed to decode webhook payload: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		received = append(received, evt)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := New([]Config{
		{
			URL:    server.URL,
			Events: []string{"block"},
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client.Start(ctx)

	client.Send(Event{Type: "block", Timestamp: time.Now().Unix(), Data: "test-blocked"})
	client.Send(Event{Type: "pass", Timestamp: time.Now().Unix(), Data: "test-passed"})

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Errorf("expected 1 webhook call (block only), got %d", len(received))
	}
	if len(received) > 0 && received[0].Type != "block" {
		t.Errorf("expected event type 'block', got %q", received[0].Type)
	}
}

func TestWebhookSendAll(t *testing.T) {
	var mu sync.Mutex
	var count int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		count++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := New([]Config{
		{
			URL:    server.URL,
			Events: []string{"all"},
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client.Start(ctx)

	client.Send(Event{Type: "block", Timestamp: time.Now().Unix()})
	client.Send(Event{Type: "pass", Timestamp: time.Now().Unix()})

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if count != 2 {
		t.Errorf("expected 2 webhook calls (all), got %d", count)
	}
}

func TestWebhookCustomHeaders(t *testing.T) {
	var receivedAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := New([]Config{
		{
			URL:     server.URL,
			Headers: map[string]string{"Authorization": "Bearer test-token"},
			Events:  []string{"all"},
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client.Start(ctx)

	client.Send(Event{Type: "block", Timestamp: time.Now().Unix()})

	time.Sleep(100 * time.Millisecond)

	if receivedAuth != "Bearer test-token" {
		t.Errorf("expected Authorization header 'Bearer test-token', got %q", receivedAuth)
	}
}

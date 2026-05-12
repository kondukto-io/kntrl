package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/kondukto-io/kntrl/pkg/logger"
)

// Config represents a single webhook destination.
type Config struct {
	URL     string            `yaml:"url"`
	Headers map[string]string `yaml:"headers"`
	Events  []string          `yaml:"events"` // "block", "all"
}

// Event is the payload sent to webhooks.
type Event struct {
	Type      string      `json:"type"` // "block", "pass"
	Timestamp int64       `json:"timestamp"`
	Data      interface{} `json:"data"`
}

// Client manages webhook dispatching.
type Client struct {
	configs    []Config
	ch         chan Event
	httpClient *http.Client
}

// New creates a new webhook client.
func New(configs []Config) *Client {
	return &Client{
		configs: configs,
		ch:      make(chan Event, 256),
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Start begins processing webhook events in the background.
func (c *Client) Start(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case evt := <-c.ch:
				c.dispatch(evt)
			}
		}
	}()
}

// Send queues an event for webhook delivery.
func (c *Client) Send(evt Event) {
	select {
	case c.ch <- evt:
	default:
		logger.Log.Warn("webhook channel full, dropping event")
	}
}

func (c *Client) dispatch(evt Event) {
	payload, err := json.Marshal(evt)
	if err != nil {
		logger.Log.Errorf("webhook marshal error: %v", err)
		return
	}

	for _, cfg := range c.configs {
		if !shouldSend(cfg.Events, evt.Type) {
			continue
		}

		req, err := http.NewRequest(http.MethodPost, cfg.URL, bytes.NewReader(payload))
		if err != nil {
			logger.Log.Errorf("webhook request error for %s: %v", cfg.URL, err)
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		for k, v := range cfg.Headers {
			req.Header.Set(k, v)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			logger.Log.Errorf("webhook send error for %s: %v", cfg.URL, err)
			continue
		}
		if resp == nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 400 {
			logger.Log.Warnf("webhook %s returned status %d", cfg.URL, resp.StatusCode)
		}
	}
}

func shouldSend(events []string, eventType string) bool {
	for _, e := range events {
		if e == "all" || e == eventType {
			return true
		}
	}
	return false
}

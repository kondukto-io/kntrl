package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/kondukto-io/kntrl/internal/core/domain"
	"github.com/kondukto-io/kntrl/pkg/ci"
	"github.com/kondukto-io/kntrl/pkg/logger"
)

// Config holds cloud upload settings.
type Config struct {
	APIURL string
	APIKey string
}

// EventPayload is sent for each real-time event via POST /api/v1/events.
type EventPayload struct {
	SessionID string       `json:"session_id"`
	Timestamp int64        `json:"timestamp"`
	EventType string       `json:"event_type"`
	CI        *ci.Metadata `json:"ci,omitempty"`
	Data      any          `json:"data"`
}

// SummaryPayload is sent at exit via POST /api/v1/sessions/summary.
type SummaryPayload struct {
	SessionID     string                     `json:"session_id"`
	StartedAt     int64                      `json:"started_at"`
	FinishedAt    int64                      `json:"finished_at"`
	CI            *ci.Metadata               `json:"ci,omitempty"`
	Mode          string                     `json:"mode"`
	NetworkEvents []domain.ReportEvent       `json:"network_events"`
	ProcessEvents []domain.ProcessReportEvent `json:"process_events"`
	DNSEvents     []domain.DNSReportEvent    `json:"dns_events"`
	FileEvents    []domain.FileReportEvent   `json:"file_events"`
	Counts        domain.SummaryCounts       `json:"counts"`
}

// authResponse holds the credentials returned by POST /api/v1/auth.
type authResponse struct {
	NatsURL   string `json:"nats_url"`
	NatsToken string `json:"nats_token"`
	SessionID string `json:"session_id"`
}

// Client manages cloud event uploads.
type Client struct {
	config           Config
	ciMeta           *ci.Metadata
	sessionID        string
	startedAt        int64
	ch               chan EventPayload
	httpClient       *http.Client
	nc               *nats.Conn
	evtSubjectPrefix string
	summarySubject   string
}

// New creates a new cloud upload client.
func New(cfg Config, ciMeta *ci.Metadata, sessionID string) *Client {
	return &Client{
		config:     cfg,
		ciMeta:     ciMeta,
		sessionID:  sessionID,
		startedAt:  time.Now().Unix(),
		ch:         make(chan EventPayload, 256),
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// Start begins processing cloud events in the background.
func (c *Client) Start(ctx context.Context) {
	authResp, err := c.authenticate()
	if err != nil {
		logger.Log.Warnf("cloud auth failed, falling back to HTTP: %v", err)
		c.startHTTPFallback(ctx)
		return
	}

	c.sessionID = authResp.SessionID
	c.evtSubjectPrefix = "kntrl.events." + authResp.SessionID
	c.summarySubject = "kntrl.sessions." + authResp.SessionID + ".summary"

	nc, err := nats.Connect(authResp.NatsURL,
		nats.Token(authResp.NatsToken),
		nats.MaxReconnects(10),
		nats.ReconnectWait(2*time.Second),
		nats.ReconnectBufSize(8*1024*1024),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			if err != nil {
				logger.Log.Warnf("NATS disconnected: %v", err)
			}
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			logger.Log.Info("NATS reconnected")
		}),
		nats.ClosedHandler(func(_ *nats.Conn) {
			logger.Log.Info("NATS connection closed")
		}),
	)
	if err != nil {
		logger.Log.Warnf("NATS connect failed, falling back to HTTP: %v", err)
		c.startHTTPFallback(ctx)
		return
	}

	c.nc = nc
	go c.publishLoop(ctx)
}

// Send queues an event for cloud delivery (non-blocking).
func (c *Client) Send(eventType string, ts int64, data any) {
	evt := EventPayload{
		SessionID: c.sessionID,
		Timestamp: ts,
		EventType: eventType,
		CI:        c.ciMeta,
		Data:      data,
	}
	select {
	case c.ch <- evt:
	default:
		logger.Log.Warn("cloud channel full, dropping event")
	}
}

// SendSummary sends the session summary synchronously at exit.
func (c *Client) SendSummary(summary SummaryPayload) error {
	summary.SessionID = c.sessionID
	summary.StartedAt = c.startedAt
	summary.FinishedAt = time.Now().Unix()
	summary.CI = c.ciMeta

	if c.nc != nil {
		data, err := json.Marshal(summary)
		if err != nil {
			return fmt.Errorf("marshal error: %w", err)
		}
		if err := c.nc.Publish(c.summarySubject, data); err != nil {
			return fmt.Errorf("NATS publish summary error: %w", err)
		}
		return c.nc.Flush()
	}

	return c.post("/api/v1/sessions/summary", summary)
}

// Close drains remaining events from the channel.
func (c *Client) Close() {
	if c.nc != nil {
		for {
			select {
			case evt := <-c.ch:
				data, err := json.Marshal(evt)
				if err != nil {
					logger.Log.Errorf("cloud marshal error on close: %v", err)
					continue
				}
				subject := c.evtSubjectPrefix + "." + evt.EventType
				if err := c.nc.Publish(subject, data); err != nil {
					logger.Log.Errorf("NATS publish error on close: %v", err)
				}
			default:
				if err := c.nc.Drain(); err != nil {
					logger.Log.Errorf("NATS drain error: %v", err)
				}
				return
			}
		}
	}

	for {
		select {
		case evt := <-c.ch:
			c.dispatchHTTP(evt)
		default:
			return
		}
	}
}

// authenticate exchanges the API key for NATS credentials via POST /api/v1/auth.
func (c *Client) authenticate() (*authResponse, error) {
	req, err := http.NewRequest(http.MethodPost, c.config.APIURL+"/api/v1/auth", nil)
	if err != nil {
		return nil, fmt.Errorf("request error: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.config.APIKey)
	req.Header.Set("User-Agent", "kntrl-agent/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth request error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("auth returned status %d", resp.StatusCode)
	}

	var authResp authResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return nil, fmt.Errorf("auth decode error: %w", err)
	}

	if authResp.NatsURL == "" {
		return nil, fmt.Errorf("auth response missing nats_url")
	}

	return &authResp, nil
}

// publishLoop reads events from the channel and publishes them via NATS.
func (c *Client) publishLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case evt := <-c.ch:
			data, err := json.Marshal(evt)
			if err != nil {
				logger.Log.Errorf("cloud marshal error: %v", err)
				continue
			}
			subject := c.evtSubjectPrefix + "." + evt.EventType
			if err := c.nc.Publish(subject, data); err != nil {
				logger.Log.Errorf("NATS publish error: %v", err)
			}
		}
	}
}

// startHTTPFallback launches the legacy HTTP dispatch goroutine.
func (c *Client) startHTTPFallback(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case evt := <-c.ch:
				c.dispatchHTTP(evt)
			}
		}
	}()
}

func (c *Client) dispatchHTTP(evt EventPayload) {
	if err := c.post("/api/v1/events", evt); err != nil {
		logger.Log.Errorf("cloud event dispatch error: %v", err)
	}
}

func (c *Client) post(path string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal error: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.config.APIURL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("request error: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.config.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "kntrl-agent/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send error: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	return nil
}

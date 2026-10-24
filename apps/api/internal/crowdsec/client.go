package crowdsec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client talks to CrowdSec LAPI with bouncer key (REQ-IDS-003/011)
// and optional local agent for scenario overrides (REQ-IDS-017).
type Client struct {
	BaseURL    string
	BouncerKey string
	AgentURL   string // e.g. http://crowdsec:8091
	AgentToken string
	HTTP       *http.Client
}

type Decision struct {
	ID       int64  `json:"id"`
	Origin   string `json:"origin"`
	Type     string `json:"type"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Duration string `json:"duration"`
	Scenario string `json:"scenario"`
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (c *Client) Enabled() bool {
	return c != nil && c.BaseURL != "" && c.BouncerKey != ""
}

// Decisions returns active decisions (ban stream snapshot).
func (c *Client) Decisions(ctx context.Context) ([]Decision, error) {
	if !c.Enabled() {
		return nil, fmt.Errorf("crowdsec client not configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.BaseURL, "/")+"/v1/decisions", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Api-Key", c.BouncerKey)
	res, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 300 {
		return nil, fmt.Errorf("crowdsec decisions %d: %s", res.StatusCode, truncate(string(body), 200))
	}
	if len(body) == 0 || string(body) == "null" {
		return []Decision{}, nil
	}
	var out []Decision
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Ping checks LAPI reachability without logging the key.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.Decisions(ctx)
	return err
}

// ApplyDetection pushes allowlisted scenario/profile YAML to crowdsec-agent (REQ-IDS-017).
func (c *Client) ApplyDetection(ctx context.Context, files map[string]string) error {
	if c == nil || c.AgentURL == "" || c.AgentToken == "" {
		return fmt.Errorf("crowdsec agent not configured")
	}
	body, _ := json.Marshal(map[string]any{"files": files})
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.AgentURL, "/")+"/v1/apply", bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Agent-Token", c.AgentToken)
		hc := c.httpClient()
		// Detection apply may HUP CrowdSec; allow longer than LAPI polls.
		if hc.Timeout > 0 && hc.Timeout < 30*time.Second {
			hc = &http.Client{Timeout: 30 * time.Second}
		}
		res, err := hc.Do(req)
		if err != nil {
			lastErr = err
			// EOF / connection reset: agent or wrapper restarted mid-apply — retry.
			if strings.Contains(err.Error(), "EOF") || strings.Contains(err.Error(), "connection reset") {
				continue
			}
			return err
		}
		raw, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode >= 300 {
			return fmt.Errorf("crowdsec agent %d: %s", res.StatusCode, truncate(string(raw), 200))
		}
		return nil
	}
	return lastErr
}

// AgentPing checks the local agent health endpoint.
func (c *Client) AgentPing(ctx context.Context) bool {
	if c == nil || c.AgentURL == "" {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.AgentURL, "/")+"/health", nil)
	if err != nil {
		return false
	}
	res, err := c.httpClient().Do(req)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	return res.StatusCode == 200
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

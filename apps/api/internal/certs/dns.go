package certs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DNSProvider creates/deletes ACME DNS-01 TXT records (REQ-SSL-005/006).
type DNSProvider interface {
	Present(ctx context.Context, domain, token, keyAuth string) error
	CleanUp(ctx context.Context, domain, token, keyAuth string) error
}

// MockDNSProvider records TXT ops for tests (REQ-SSL-006 mock).
type MockDNSProvider struct {
	mu      sync.Mutex
	Records map[string]string // fqdn -> value
}

func NewMockDNS() *MockDNSProvider {
	return &MockDNSProvider{Records: map[string]string{}}
}

func (m *MockDNSProvider) Present(_ context.Context, domain, _, txtValue string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Records[acmeTXTName(domain)] = txtValue
	return nil
}

func (m *MockDNSProvider) CleanUp(_ context.Context, domain, _, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.Records, acmeTXTName(domain))
	return nil
}

func acmeTXTName(domain string) string {
	d := strings.TrimPrefix(domain, "*.")
	return "_acme-challenge." + d
}

// CloudflareDNS implements Cloudflare API DNS-01 (REQ-SSL-006).
type CloudflareDNS struct {
	APIToken   string
	HTTPClient *http.Client
	BaseURL    string // override for tests
	zoneCache  map[string]string
	recordIDs  map[string]string // fqdn -> record id
	mu         sync.Mutex
}

func NewCloudflareDNS(apiToken string) *CloudflareDNS {
	return &CloudflareDNS{
		APIToken:   apiToken,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		BaseURL:    "https://api.cloudflare.com/client/v4",
		zoneCache:  map[string]string{},
		recordIDs:  map[string]string{},
	}
}

func (c *CloudflareDNS) Present(ctx context.Context, domain, _, txtValue string) error {
	// txtValue here must already be the DNS-01 digest
	fqdn := acmeTXTName(domain)
	zoneID, err := c.findZone(ctx, domain)
	if err != nil {
		return err
	}
	body := map[string]any{
		"type":    "TXT",
		"name":    fqdn,
		"content": txtValue,
		"ttl":     120,
	}
	var resp struct {
		Success bool `json:"success"`
		Result  struct {
			ID string `json:"id"`
		} `json:"result"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/zones/"+zoneID+"/dns_records", body, &resp); err != nil {
		return err
	}
	if !resp.Success {
		msg := "cloudflare create failed"
		if len(resp.Errors) > 0 {
			msg = resp.Errors[0].Message
		}
		return fmt.Errorf("%s", msg)
	}
	c.mu.Lock()
	c.recordIDs[fqdn] = resp.Result.ID
	c.mu.Unlock()
	return nil
}

func (c *CloudflareDNS) CleanUp(ctx context.Context, domain, _, _ string) error {
	fqdn := acmeTXTName(domain)
	c.mu.Lock()
	id := c.recordIDs[fqdn]
	c.mu.Unlock()
	if id == "" {
		return nil
	}
	zoneID, err := c.findZone(ctx, domain)
	if err != nil {
		return err
	}
	var resp struct {
		Success bool `json:"success"`
	}
	_ = c.doJSON(ctx, http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+id, nil, &resp)
	c.mu.Lock()
	delete(c.recordIDs, fqdn)
	c.mu.Unlock()
	return nil
}

func (c *CloudflareDNS) findZone(ctx context.Context, domain string) (string, error) {
	d := strings.TrimPrefix(domain, "*.")
	parts := strings.Split(d, ".")
	c.mu.Lock()
	if z, ok := c.zoneCache[d]; ok {
		c.mu.Unlock()
		return z, nil
	}
	c.mu.Unlock()
	for i := 0; i < len(parts)-1; i++ {
		candidate := strings.Join(parts[i:], ".")
		var resp struct {
			Success bool `json:"success"`
			Result  []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"result"`
		}
		q := "/zones?name=" + candidate
		if err := c.doJSON(ctx, http.MethodGet, q, nil, &resp); err != nil {
			continue
		}
		if resp.Success && len(resp.Result) > 0 {
			c.mu.Lock()
			c.zoneCache[d] = resp.Result[0].ID
			c.mu.Unlock()
			return resp.Result[0].ID, nil
		}
	}
	return "", fmt.Errorf("cloudflare zone not found for %s", domain)
}

func (c *CloudflareDNS) doJSON(ctx context.Context, method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIToken)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("cloudflare decode: %w (%s)", err, string(raw))
		}
	}
	if res.StatusCode >= 300 {
		return fmt.Errorf("cloudflare HTTP %d: %s", res.StatusCode, string(raw))
	}
	return nil
}

package wafingest

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nginx-proxy-waf/api/internal/db"
	"github.com/nginx-proxy-waf/api/internal/models"
	"github.com/nginx-proxy-waf/api/internal/wafmask"
)

// Worker tails ModSecurity JSON audit log into security_events (REQ-WAF-009/012).
type Worker struct {
	Store   *db.Store
	LogPath string
	Log     *slog.Logger
}

func (w *Worker) Run(ctx context.Context) {
	offset := int64(0)
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, err := w.consume(ctx, offset)
			if err != nil {
				if !os.IsNotExist(err) {
					w.Log.Debug("wafingest", "err", err)
				}
				continue
			}
			offset = n
		}
	}
}

func (w *Worker) consume(ctx context.Context, offset int64) (int64, error) {
	f, err := os.Open(w.LogPath)
	if err != nil {
		return offset, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return offset, err
	}
	if st.Size() < offset {
		offset = 0 // rotated
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return offset, err
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		ev, ok := parseAuditLine(line)
		if !ok {
			continue
		}
		if ev.Domain != "" && ev.HostID == nil {
			if id, err := w.Store.FindHostIDByDomain(ctx, ev.Domain); err == nil {
				ev.HostID = &id
			}
		}
		if _, err := w.Store.InsertSecurityEvent(ctx, ev); err != nil {
			w.Log.Error("wafingest insert", "err", err)
		}
	}
	pos, _ := f.Seek(0, io.SeekCurrent)
	return pos, sc.Err()
}

func parseAuditLine(line string) (models.SecurityEvent, bool) {
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return models.SecurityEvent{}, false
	}

	ev := models.SecurityEvent{Source: "waf"}
	// Host/domain + client_ip before MaskMap — dotted values can match JWT-like redaction.
	if tx, ok := raw["transaction"].(map[string]any); ok {
		if v, ok := tx["client_ip"].(string); ok {
			ev.ClientIP = v
		}
		if req, ok := tx["request"].(map[string]any); ok {
			if headers, ok := req["headers"].(map[string]any); ok {
				ev.Domain = normalizeEventHost(headerString(headers, "Host", "host"))
			}
		}
	}

	wafmask.MaskMap(raw)

	if tx, ok := raw["transaction"].(map[string]any); ok {
		if ev.ClientIP == "" {
			if v, ok := tx["client_ip"].(string); ok {
				ev.ClientIP = v
			}
		}
		if v, ok := tx["unique_id"].(string); ok {
			ev.UniqueID = v
		}
		if v, ok := tx["time_stamp"].(string); ok && ev.UniqueID == "" {
			ev.UniqueID = v
		}
		if req, ok := tx["request"].(map[string]any); ok {
			if v, ok := req["uri"].(string); ok {
				ev.URI = wafmask.Mask(v)
			}
			if v, ok := req["method"].(string); ok {
				ev.Method = v
			}
		}
		if msgs, ok := tx["messages"].([]any); ok && len(msgs) > 0 {
			if m0, ok := msgs[0].(map[string]any); ok {
				if v, ok := m0["message"].(string); ok {
					ev.Message = wafmask.Mask(v)
				}
				if details, ok := m0["details"].(map[string]any); ok {
					if v, ok := details["ruleId"].(string); ok {
						ev.RuleID = v
					} else if v, ok := details["ruleId"].(float64); ok {
						ev.RuleID = strconv.FormatInt(int64(v), 10)
					}
					if v, ok := details["severity"].(string); ok {
						ev.Severity = severityToInt(v)
					} else if v, ok := details["severity"].(float64); ok {
						ev.Severity = int(v)
					}
					if data, ok := details["data"].(string); ok {
						ev.PayloadSummary = wafmask.Mask(data)
					}
				}
			}
		}
	}
	// Alternate flat schema
	if ev.RuleID == "" {
		if v, ok := raw["rule_id"].(string); ok {
			ev.RuleID = v
		}
	}
	if ev.Message == "" {
		if v, ok := raw["message"].(string); ok {
			ev.Message = wafmask.Mask(v)
		}
	}
	if ev.RuleID == "" && ev.Message == "" {
		return ev, false
	}
	if ev.PayloadSummary == "" {
		b, _ := json.Marshal(raw)
		ev.PayloadSummary = wafmask.Mask(string(b))
	}
	return ev, true
}

func severityToInt(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL", "2":
		return 2
	case "ERROR", "3":
		return 3
	case "WARNING", "4":
		return 4
	case "NOTICE", "5":
		return 5
	default:
		return 0
	}
}

func headerString(headers map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := headers[k].(string); ok && v != "" {
			return v
		}
	}
	// Case-insensitive fallback
	for hk, hv := range headers {
		for _, k := range keys {
			if strings.EqualFold(hk, k) {
				if v, ok := hv.(string); ok && v != "" {
					return v
				}
			}
		}
	}
	return ""
}

// normalizeEventHost strips port and brackets from Host / :authority values.
func normalizeEventHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	// [IPv6]:port
	if strings.HasPrefix(host, "[") {
		if i := strings.Index(host, "]"); i > 0 {
			return host[1:i]
		}
	}
	// hostname:port (not IPv6)
	if i := strings.LastIndex(host, ":"); i > 0 && strings.Count(host, ":") == 1 {
		return host[:i]
	}
	return host
}

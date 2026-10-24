package nginxcfg

import (
	"fmt"
	"strings"
)

// Access log format presets (REQ-PROXY-009) — allowlisted only; never free-form (REQ-CFG-008).
// Nginx names use nsp_ prefix to avoid colliding with CRS/distro built-ins (e.g. "combined").
var AccessLogFormats = map[string]string{
	"main": `$remote_addr - $remote_user [$time_local] "$request" ` +
		`$status $body_bytes_sent "$http_referer" "$http_user_agent"`,
	"combined": `$remote_addr - $remote_user [$time_local] "$request" ` +
		`$status $body_bytes_sent "$http_referer" "$http_user_agent"`,
	"detailed": `$remote_addr - $remote_user [$time_local] "$request" ` +
		`$status $body_bytes_sent "$http_referer" "$http_user_agent" ` +
		`rt=$request_time uct="$upstream_connect_time" uht="$upstream_header_time" urt="$upstream_response_time"`,
	"json": `{"time":"$time_iso8601","remote_addr":"$remote_addr","method":"$request_method",` +
		`"uri":"$request_uri","status":$status,"bytes":$body_bytes_sent,` +
		`"referer":"$http_referer","ua":"$http_user_agent","host":"$host",` +
		`"request_time":"$request_time","upstream_status":"$upstream_status"}`,
}

// NginxFormatName maps API preset → nginx log_format name.
func NginxFormatName(preset string) string {
	switch NormalizeAccessLogFormat(preset) {
	case "combined":
		return "nsp_combined"
	case "detailed":
		return "nsp_detailed"
	case "json":
		return "nsp_json"
	default:
		return "nsp_main"
	}
}

// NormalizeAccessLogFormat returns an allowlisted format name (default main).
func NormalizeAccessLogFormat(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "main"
	}
	if _, ok := AccessLogFormats[s]; ok {
		return s
	}
	return ""
}

func ValidateAccessLogFormat(s string) error {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	if NormalizeAccessLogFormat(s) == "" {
		return fmt.Errorf("invalid access_log_format %q (allowed: main, combined, detailed, json)", s)
	}
	return nil
}

// RenderLogFormatsBlock emits nsp_* presets into http{} (REQ-PROXY-009).
// Also defines legacy "main" for older proxy_host confs until next apply.
func RenderLogFormatsBlock() string {
	var b strings.Builder
	b.WriteString("    log_format nsp_main '" + AccessLogFormats["main"] + "';\n")
	b.WriteString("    log_format main '" + AccessLogFormats["main"] + "';\n") // compat
	b.WriteString("    log_format nsp_combined '" + AccessLogFormats["combined"] + "';\n")
	b.WriteString("    log_format nsp_detailed '" + AccessLogFormats["detailed"] + "';\n")
	b.WriteString("    log_format nsp_json escape=json '" + AccessLogFormats["json"] + "';\n")
	return b.String()
}

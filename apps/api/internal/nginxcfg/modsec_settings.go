package nginxcfg

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ModSecGlobalSettings are allowlisted ModSecurity directives (REQ-WAF-017).
// Free-form nginx/ModSec config is rejected — only these fields.
type ModSecGlobalSettings struct {
	AuditEngine            string `json:"audit_engine"`              // On | Off | RelevantOnly
	DebugLogLevel          int    `json:"debug_log_level"`           // 0..9
	AuditLogParts          string `json:"audit_log_parts"`           // e.g. ABIJDEFHZ
	AuditLogRelevantStatus string `json:"audit_log_relevant_status"` // regex
	AuditLogType           string `json:"audit_log_type"`            // Serial | Concurrent
	RequestBodyAccess      string `json:"request_body_access"`       // On | Off
	ResponseBodyAccess     string `json:"response_body_access"`      // On | Off
	RequestBodyLimit       int    `json:"request_body_limit"`        // bytes
}

var (
	auditPartsRe   = regexp.MustCompile(`^[A-Z]{1,32}$`)
	auditStatusRe  = regexp.MustCompile(`^[\^\$\(\)\[\]\|\?\*\+\.\\d\w\-!:]{1,128}$`)
	onOffRe        = regexp.MustCompile(`^(On|Off)$`)
)

func DefaultModSecGlobalSettings() ModSecGlobalSettings {
	return ModSecGlobalSettings{
		AuditEngine:            "RelevantOnly",
		DebugLogLevel:          0,
		AuditLogParts:          "ABIJDEFHZ",
		AuditLogRelevantStatus: `^(?:5|4(?!04))`,
		AuditLogType:           "Serial",
		RequestBodyAccess:      "On",
		ResponseBodyAccess:     "Off",
		RequestBodyLimit:       13107200,
	}
}

func (s *ModSecGlobalSettings) Normalize() {
	d := DefaultModSecGlobalSettings()
	if s.AuditEngine == "" {
		s.AuditEngine = d.AuditEngine
	}
	if s.AuditLogParts == "" {
		s.AuditLogParts = d.AuditLogParts
	}
	if s.AuditLogRelevantStatus == "" {
		s.AuditLogRelevantStatus = d.AuditLogRelevantStatus
	}
	if s.AuditLogType == "" {
		s.AuditLogType = d.AuditLogType
	}
	if s.RequestBodyAccess == "" {
		s.RequestBodyAccess = d.RequestBodyAccess
	}
	if s.ResponseBodyAccess == "" {
		s.ResponseBodyAccess = d.ResponseBodyAccess
	}
	if s.RequestBodyLimit == 0 {
		s.RequestBodyLimit = d.RequestBodyLimit
	}
}

func (s ModSecGlobalSettings) Validate() error {
	s.Normalize()
	switch s.AuditEngine {
	case "On", "Off", "RelevantOnly":
	default:
		return fmt.Errorf("audit_engine must be On|Off|RelevantOnly")
	}
	if s.DebugLogLevel < 0 || s.DebugLogLevel > 9 {
		return fmt.Errorf("debug_log_level must be 0..9")
	}
	if !auditPartsRe.MatchString(s.AuditLogParts) {
		return fmt.Errorf("invalid audit_log_parts")
	}
	if !auditStatusRe.MatchString(s.AuditLogRelevantStatus) {
		return fmt.Errorf("invalid audit_log_relevant_status")
	}
	switch s.AuditLogType {
	case "Serial", "Concurrent":
	default:
		return fmt.Errorf("audit_log_type must be Serial|Concurrent")
	}
	if !onOffRe.MatchString(s.RequestBodyAccess) {
		return fmt.Errorf("request_body_access must be On|Off")
	}
	if !onOffRe.MatchString(s.ResponseBodyAccess) {
		return fmt.Errorf("response_body_access must be On|Off")
	}
	if s.RequestBodyLimit < 1024 || s.RequestBodyLimit > 104857600 {
		return fmt.Errorf("request_body_limit must be 1KiB..100MiB")
	}
	return nil
}

// RenderModSecGlobalSettings emits allowlisted directives for overlay (REQ-WAF-017).
func RenderModSecGlobalSettings(s ModSecGlobalSettings) (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	s.Normalize()
	var b strings.Builder
	b.WriteString("# REQ-WAF-017 — global ModSecurity settings\n")
	b.WriteString("SecAuditEngine " + s.AuditEngine + "\n")
	b.WriteString("SecDebugLogLevel " + strconv.Itoa(s.DebugLogLevel) + "\n")
	b.WriteString("SecAuditLogParts " + s.AuditLogParts + "\n")
	b.WriteString(`SecAuditLogRelevantStatus "` + escapeModSec(s.AuditLogRelevantStatus) + `"` + "\n")
	b.WriteString("SecAuditLogType " + s.AuditLogType + "\n")
	b.WriteString("SecRequestBodyAccess " + s.RequestBodyAccess + "\n")
	b.WriteString("SecResponseBodyAccess " + s.ResponseBodyAccess + "\n")
	b.WriteString("SecRequestBodyLimit " + strconv.Itoa(s.RequestBodyLimit) + "\n")
	return b.String(), nil
}

package nginxcfg

import "math"

// DefaultRetryAfterSeconds derives a client hint from RPS (REQ-RATE-005).
// Example: 10 r/s → 1s; 0.5 r/s → 2s.
func DefaultRetryAfterSeconds(rps float64) int {
	if rps <= 0 {
		return 1
	}
	s := int(math.Ceil(1.0 / rps))
	if s < 1 {
		return 1
	}
	if s > 3600 {
		return 3600
	}
	return s
}

// NormalizeRetryAfterSeconds clamps or defaults from RPS when unset (0).
func NormalizeRetryAfterSeconds(sec int, rps float64) int {
	if sec <= 0 {
		return DefaultRetryAfterSeconds(rps)
	}
	if sec > 3600 {
		return 3600
	}
	return sec
}

// Package severity provides ordered severity comparison used by both
// `sbomhub scan --fail-on` and `sbomhub check --fail-on`. Centralising
// the comparison means both commands enforce thresholds identically.
package severity

import "strings"

// Level is an ordinal severity ranking. Higher = worse. The KEV bucket
// is conceptually orthogonal to CVSS severity (a KEV CVE could be of any
// severity) but is treated as "above critical" for --fail-on purposes:
// any presence in CISA's Known Exploited Vulnerabilities catalogue is the
// loudest possible signal we have.
type Level int

const (
	LevelNone Level = iota
	LevelLow
	LevelMedium
	LevelHigh
	LevelCritical
	LevelKEV
)

// Parse maps a CLI string (case-insensitive) to a Level. Unknown values
// return LevelNone, which the caller should treat as "fail-on disabled".
func Parse(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "kev":
		return LevelKEV
	case "critical":
		return LevelCritical
	case "high":
		return LevelHigh
	case "medium":
		return LevelMedium
	case "low":
		return LevelLow
	default:
		return LevelNone
	}
}

// Counts holds vulnerability counts by severity bucket. Mirrors the JSON
// shape returned by the API's scan-status endpoint.
//
// `Unknown` represents vulnerabilities the server could not map to a CVSS
// severity (data quality gap, NVD enrichment lag, etc.). It is reported
// to the operator for visibility but is intentionally NOT considered by
// ShouldFail — promoting "unknown" to a CI-blocking signal would punish
// users for upstream data gaps rather than real risk. The presence of a
// nonzero Unknown bucket should still surface in CLI output so the
// operator can investigate; see scan.go formatScanVulnSummary.
type Counts struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Unknown  int
	KEV      int
}

// ShouldFail reports whether the observed counts trip the configured
// threshold. The rule is "any vulnerability AT OR ABOVE the threshold
// fails", e.g. --fail-on high fires for High OR Critical OR KEV.
//
// Returns false when threshold == LevelNone (i.e. the user did not pass
// --fail-on at all) so callers can use the same code path with and
// without the flag set.
func ShouldFail(c Counts, threshold Level) bool {
	if threshold == LevelNone {
		return false
	}
	if threshold <= LevelKEV && c.KEV > 0 {
		return true
	}
	if threshold <= LevelCritical && c.Critical > 0 {
		return true
	}
	if threshold <= LevelHigh && c.High > 0 {
		return true
	}
	if threshold <= LevelMedium && c.Medium > 0 {
		return true
	}
	if threshold <= LevelLow && c.Low > 0 {
		return true
	}
	return false
}

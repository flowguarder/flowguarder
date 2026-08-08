// Package anomaly provides deterministic anomaly detection heuristics for
// Kubernetes network flows. Each detector is a pure function with no
// randomness or I/O side effects.
package anomaly

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/flowguarder/flowguarder/pkg/analyze"
	"github.com/flowguarder/flowguarder/pkg/config"
	"github.com/flowguarder/flowguarder/pkg/flow"
)

// Pattern is an alias for analyze.Pattern so anomaly detectors and
// consumers (policy.Build, report printers) work with a single type.
type Pattern = analyze.Pattern

// Severity levels for anomalies.
type Severity string

const (
	SeverityInfo   Severity = "info"
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

// Anomaly represents a single detected anomaly.
type Anomaly struct {
	ID          string         `json:"id"`
	Type        string         `json:"type"`
	Severity    Severity       `json:"severity"`
	Workload    string         `json:"workload"`
	Description string         `json:"description"`
	Evidence    map[string]any `json:"evidence"`
	DetectedAt  time.Time      `json:"detected_at"`
}

// NewAnomaly creates a new Anomaly with a deterministic hash-based ID.
func NewAnomaly(anomalyType string, severity Severity, workload, description string, evidence map[string]any) Anomaly {
	key := fmt.Sprintf("%s|%s|%s", anomalyType, workload, description)
	h := sha256.Sum256([]byte(key))
	return Anomaly{
		ID:          fmt.Sprintf("%x", h[:8]),
		Type:        anomalyType,
		Severity:    severity,
		Workload:    workload,
		Description: description,
		Evidence:    evidence,
		DetectedAt:  time.Now().UTC(),
	}
}

// severityByCount adjusts a base severity based on the observed count.
// Single-occurrence anomalies are downgraded one level (floor: info).
// High-volume anomalies (>= 100) are upgraded one level (cap: high).
func severityByCount(base Severity, count uint64) Severity {
	switch base {
	case SeverityHigh:
		if count >= 100 {
			return SeverityHigh
		}
		if count == 1 {
			return SeverityMedium
		}
		return SeverityHigh
	case SeverityMedium:
		if count >= 100 {
			return SeverityHigh
		}
		if count == 1 {
			return SeverityLow
		}
		return SeverityMedium
	case SeverityLow, SeverityInfo:
		if count >= 100 {
			return SeverityMedium
		}
		return base
	}
	return base
}

// Detector is the interface every anomaly detector must implement.
type Detector interface {
	// Detect takes flows, patterns, workloads and config and returns a list
	// of anomalies. It must be side-effect free and deterministic given the
	// same inputs.
	Detect(flows []flow.Flow, patterns []Pattern, workloads analyze.Workloads, cfg config.Config) []Anomaly
}

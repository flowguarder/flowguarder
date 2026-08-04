package anomaly

import (
	"github.com/flowguarder/flowguarder/pkg/analyze"
	"github.com/flowguarder/flowguarder/pkg/config"
	"github.com/flowguarder/flowguarder/pkg/flow"
)

// RareFlowDetector flags patterns with frequency below the configured
// RareFlowThreshold percentile of total pattern traffic.
type RareFlowDetector struct{}

var _ Detector = (*RareFlowDetector)(nil)

// Detect returns one anomaly per pattern whose frequency is below
// cfg.RareFlowThreshold fraction of the sum of all pattern counts.
func (d *RareFlowDetector) Detect(
	flows []flow.Flow,
	patterns []Pattern,
	workloads analyze.Workloads,
	cfg config.Config,
) []Anomaly {
	if len(patterns) == 0 {
		return nil
	}

	// Calculate total count for percentile threshold.
	var totalCount uint64
	for _, p := range patterns {
		// Accumulate both directions so we capture round-trip traffic.
		totalCount += p.Count
	}

	// Pre-count distinct patterns per source workload to detect scrapers/controllers.
	patternsPerSrc := make(map[string]int)
	for _, p := range patterns {
		patternsPerSrc[p.SrcWorkloadID]++
	}

	var anomalies []Anomaly
	for _, p := range patterns {
		if totalCount == 0 {
			break
		}
		ratio := float64(p.Count) / float64(totalCount)
		// Skip long-tail scrapers/controllers whose pattern count exceeds 20.
		if patternsPerSrc[p.SrcWorkloadID] > 20 {
			continue
		}
		// Flag only when both ratio AND count are below thresholds.
		if ratio < cfg.RareFlowThreshold && p.Count < 10 {
			anomalies = append(anomalies, NewAnomaly(
				"rare-flow",
				severityByCount(SeverityLow, p.Count),
				p.SrcWorkloadID,
				"Pattern has unusually low frequency",
				map[string]any{
					"source_workload": p.SrcWorkloadID,
					"dest_workload":   p.DstWorkloadID,
					"port":            p.Port,
					"protocol":        p.Protocol,
					"count":           p.Count,
					"total_patterns":  len(patterns),
					"total_events":    totalCount,
					"frequency_ratio": ratio,
					"threshold":       cfg.RareFlowThreshold,
				},
			))
		}
	}
	return anomalies
}

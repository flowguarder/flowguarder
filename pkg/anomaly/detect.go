package anomaly

import (
	"sort"

	"github.com/flowguarder/flowguarder/pkg/analyze"
	"github.com/flowguarder/flowguarder/pkg/config"
	"github.com/flowguarder/flowguarder/pkg/flow"
)

// RunAll runs all registered anomaly detectors and returns the combined,
// deduplicated list of anomalies sorted by severity then workload.
func RunAll(
	flows []flow.Flow,
	patterns []Pattern,
	workloads analyze.Workloads,
	cfg config.Config,
) []Anomaly {
	detectors := []Detector{
		&RareFlowDetector{},
		&DroppedDetector{},
		&NamespaceDetector{},
		&PortScanDetector{},
		&PublicEgressDetector{},
		&TLSDetector{},
		&AsymmetricDetector{},
	}

	all := make([]Anomaly, 0)
	for _, d := range detectors {
		anomalies := d.Detect(flows, patterns, workloads, cfg)
		all = append(all, anomalies...)
	}

	// Sort deterministically: by severity (high first), then workload, then type.
	sortAnomalies(all)
	return all
}

func sortAnomalies(anomalies []Anomaly) {
	sort.Slice(anomalies, func(i, j int) bool {
		// Higher severity first.
		severityOrder := map[Severity]int{
			SeverityHigh:   0,
			SeverityMedium: 1,
			SeverityLow:    2,
			SeverityInfo:   3,
		}
		oi := severityOrder[anomalies[i].Severity]
		oj := severityOrder[anomalies[j].Severity]
		if oi != oj {
			return oi < oj
		}
		// Then by workload.
		if anomalies[i].Workload != anomalies[j].Workload {
			return anomalies[i].Workload < anomalies[j].Workload
		}
		// Then by type.
		return anomalies[i].Type < anomalies[j].Type
	})
}

package anomaly

import (
	"fmt"
	"sort"

	"github.com/flowguarder/flowguarder/pkg/analyze"
	"github.com/flowguarder/flowguarder/pkg/config"
	"github.com/flowguarder/flowguarder/pkg/flow"
)

// DroppedDetector flags flows that were dropped/denied by policy.
type DroppedDetector struct{}

var _ Detector = (*DroppedDetector)(nil)

// Detect walks the flows and collects dropped ones, grouping by source
// workload. Each source workload with at least one dropped flow gets one
// anomaly entry.
func (d *DroppedDetector) Detect(
	flows []flow.Flow,
	patterns []Pattern,
	workloads analyze.Workloads,
	cfg config.Config,
) []Anomaly {
	droppedBySrc := make(map[string]*dropGroup)

	for _, f := range flows {
		if f.Verdict != flow.Dropped && f.Verdict != flow.Denied {
			continue
		}
		srcWID := resolveWorkloadID(f.Source, workloads)
		if srcWID == "" {
			srcWID = fmt.Sprintf("%s/unknown", f.Source.Namespace)
		}
		group, ok := droppedBySrc[srcWID]
		if !ok {
			group = &dropGroup{flows: make([]flow.Flow, 0)}
			droppedBySrc[srcWID] = group
		}
		group.flows = append(group.flows, f)
		key := patternKey(f)
		if !hasPattern(group.patterns, key) {
			group.patterns = append(group.patterns, key)
		}
	}

	if len(droppedBySrc) == 0 {
		return nil
	}

	anomalies := make([]Anomaly, 0, len(droppedBySrc))
	// Deterministic ordering by source workload ID.
	for _, src := range sortedWorkloadKeys(droppedBySrc) {
		g := droppedBySrc[src]
		anomalies = append(anomalies, NewAnomaly(
			"dropped-flow",
			SeverityMedium,
			src,
			"Traffic was dropped or denied by policy",
			map[string]any{
				"source_workload":  src,
				"drop_count":       len(g.flows),
				"pattern_count":    len(g.patterns),
				"blocked_patterns": g.patterns,
			},
		))
	}
	return anomalies
}

// --- helpers ---

type dropGroup struct {
	flows    []flow.Flow
	patterns []string
}

func resolveWorkloadID(ep flow.Endpoint, workloads analyze.Workloads) string {
	for id, w := range workloads {
		if w.Namespace == ep.Namespace && w.Name != "" {
			if w.Labels != nil {
				if ep.Labels != nil {
					// Check if any label matches: this flow endpoint belongs to this workload.
					for k, v := range w.Labels {
						if ep.Labels[k] == v {
							return string(id)
						}
					}
				}
				// Fallback: same pod name
				if ep.PodName != "" && w.Name != "" {
					// Try to strip hash from both and compare
					if stripHash(ep.PodName) == stripHash(w.Name) {
						return string(id)
					}
				}
			}
		}
	}
	return ""
}

func stripHash(s string) string {
	// Simple dash-based stripping — same heuristic as StripPodTemplateHash.
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '-' {
			return s[:i]
		}
	}
	return s
}

func patternKey(f flow.Flow) string {
	return fmt.Sprintf("%s:%d/%s", f.Destination.IP, f.Layer4.DestPort, f.Layer4.Protocol)
}

func hasPattern(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func sortedWorkloadKeys(m map[string]*dropGroup) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

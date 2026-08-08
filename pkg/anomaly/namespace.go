package anomaly

import (
	"fmt"

	"github.com/flowguarder/flowguarder/pkg/analyze"
	"github.com/flowguarder/flowguarder/pkg/config"
	"github.com/flowguarder/flowguarder/pkg/flow"
)

// NamespaceDetector flags flows where source and destination namespaces
// are not allowed nor the same.
type NamespaceDetector struct{}

var _ Detector = (*NamespaceDetector)(nil)

// Detect inspects each flow's source and destination namespaces. If they
// are the same, the flow is silently allowed. Otherwise the flow is
// checked against cfg.AllowedNamespacePairs. Anomalies are grouped per
// source-destination namespace pair.
func (d *NamespaceDetector) Detect(
	flows []flow.Flow,
	patterns []Pattern,
	workloads analyze.Workloads,
	cfg config.Config,
) []Anomaly {
	seen := make(map[string]*nsGroup)

	for _, f := range flows {
		srcNS := f.Source.Namespace
		dstNS := f.Destination.Namespace

		// Skip synthetic Goldmane peers (world ingress/egress).
		if srcNS == "" || srcNS == "-" || dstNS == "" || dstNS == "-" {
			continue
		}

		// Same-namespace flows are always allowed.
		if srcNS == dstNS {
			continue
		}

		// Check if srcNS is allowed to talk to dstNS.
		if allowedTargets, ok := cfg.AllowedNamespacePairs[srcNS]; ok {
			allowed := false
			for _, target := range allowedTargets {
				if target == dstNS {
					allowed = true
					break
				}
			}
			if allowed {
				continue
			}
		}

		key := srcNS + "→" + dstNS
		g, ok := seen[key]
		if !ok {
			g = &nsGroup{count: 0}
			seen[key] = g
		}
		g.count++
		// Record a representative workload for evidence.
		// resolveWorkloadID can return "" when the source endpoint is not in
		// the workloads map (e.g. a synthetic peer or world endpoint).  In
		// that case we fall back to an external label derived from the
		// endpoint IP when available, otherwise the source namespace.
		if g.RepresentativeWorkload == "" {
			srcWID := resolveWorkloadID(f.Source, workloads)
			if srcWID == "" {
				if f.Source.IP != "" {
					srcWID = fmt.Sprintf("external/%s", f.Source.IP)
				} else {
					srcWID = fmt.Sprintf("%s/unknown", srcNS)
				}
			}
			g.RepresentativeWorkload = srcWID
		}
	}

	if len(seen) == 0 {
		return nil
	}

	anomalies := make([]Anomaly, 0, len(seen))
	sev := SeverityMedium
	var configNote string
	if len(cfg.AllowedNamespacePairs) == 0 {
		sev = SeverityLow
		configNote = "no allowed_namespace_pairs configured; cross-namespace pairs are informational only"
	}
	for pair, g := range seen {
		evidence := map[string]any{
			"pair":               pair,
			"flow_count":         g.count,
			"representative_src": g.RepresentativeWorkload,
			"allowed_pairs":      cfg.AllowedNamespacePairs,
		}
		if configNote != "" {
			evidence["config_note"] = configNote
		}
		severity := sev
		severity = severityByCount(severity, uint64(g.count))
		anomalies = append(anomalies, NewAnomaly(
			"namespace",
			severity,
			g.RepresentativeWorkload,
			fmt.Sprintf("Cross-namespace traffic in unexpected namespace pair: %s", pair),
			evidence,
		))
	}
	return anomalies
}

type nsGroup struct {
	count                  int
	RepresentativeWorkload string
}

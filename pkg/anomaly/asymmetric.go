package anomaly

import (
	"strings"

	"github.com/flowguarder/flowguarder/pkg/analyze"
	"github.com/flowguarder/flowguarder/pkg/config"
	"github.com/flowguarder/flowguarder/pkg/flow"
)

// AsymmetricDetector flags workloads with high egress pattern count but
// near-zero ingress pattern count, suggesting unusual outbound-only traffic
// (e.g., potential data exfiltration). CronJob-labeled workloads are skipped.
type AsymmetricDetector struct{}

type flowDirInfo struct {
	egressBytes  uint64
	ingressBytes uint64
}

const (
	// DefaultAsymmetricRatio is the egress/ingress ratio threshold.
	// If egress_patterns / max(ingress_patterns, 1) >= this value, flag.
	DefaultAsymmetricRatio = 10.0
)

var _ Detector = (*AsymmetricDetector)(nil)

// Detect computes egress and ingress pattern counts per workload from
// the provided patterns slice. Workloads with an asymmetric ratio
// exceeding cfg's configured threshold (or DefaultAsymmetricRatio if 0)
// are flagged. CronJob-labeled workloads are excluded.
func (d *AsymmetricDetector) Detect(
	flows []flow.Flow,
	patterns []Pattern,
	workloads analyze.Workloads,
	cfg config.Config,
) []Anomaly {
	// Recompute using raw flow directions for accuracy.
	dirCounts := make(map[string]*flowDirInfo)

	for _, f := range flows {
		srcWID := resolveWorkloadID(f.Source, workloads)
		if srcWID == "" {
			srcWID = f.Source.IP
		}
		info, ok := dirCounts[srcWID]
		if !ok {
			info = &flowDirInfo{}
			dirCounts[srcWID] = info
		}
		switch f.Direction {
		case flow.Egress:
			info.egressBytes += f.Bytes
		case flow.Ingress:
			info.ingressBytes += f.Bytes
		}
	}

	ratio := cfg.AsymmetricRatio
	if ratio == 0 {
		ratio = DefaultAsymmetricRatio
	}

	var anomalies []Anomaly
	// Deterministic ordering.
	for _, wid := range sortedWorkloadKeys2(dirCounts) {
		info := dirCounts[wid]

		// Skip CronJob-labeled workloads.
		w, ok := workloads[analyze.WorkloadID(wid)]
		if ok && isControllerLike(w) {
			continue
		}

		// Skip workloads with no egress traffic.
		if info.egressBytes == 0 {
			continue
		}

		ingressBytes := info.ingressBytes
		if ingressBytes == 0 {
			ingressBytes = 1 // Avoid division by zero
		}

		r := float64(info.egressBytes) / float64(ingressBytes)
		if r < ratio {
			continue
		}

		anomalies = append(anomalies, NewAnomaly(
			"asymmetric-traffic",
			SeverityMedium,
			wid,
			"Highly asymmetric traffic pattern (egress much greater than ingress)",
			map[string]any{
				"source_workload": wid,
				"egress_bytes":    info.egressBytes,
				"ingress_bytes":   info.ingressBytes,
				"ratio":           r,
			},
		))
	}
	return anomalies
}

func isControllerLike(w analyze.Workload) bool {
	if w.Labels == nil {
		return false
	}
	// Existing CronJob check.
	if _, ok := w.Labels[analyze.WorkloadKeyJobName]; ok {
		return true
	}
	if _, ok := w.Labels[analyze.WorkloadKeyControllerUID]; ok {
		return true
	}
	// Namespace suffix heuristics.
	if strings.HasSuffix(w.Namespace, "-system") || strings.HasSuffix(w.Namespace, "-operator") {
		return true
	}
	// Label value containing operator/controller (case-insensitive).
	for _, v := range w.Labels {
		lv := strings.ToLower(v)
		if strings.Contains(lv, "operator") || strings.Contains(lv, "controller") {
			return true
		}
	}
	// Workload name containing operator (case-insensitive).
	if strings.Contains(strings.ToLower(w.Name), "operator") {
		return true
	}
	return false
}

func sortedWorkloadKeys2(m map[string]*flowDirInfo) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Deterministic sort.
	sortStrings(keys)
	return keys
}

func sortStrings(s []string) {
	for i := 0; i < len(s); i++ {
		for j := i + 1; j < len(s); j++ {
			if s[i] > s[j] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}

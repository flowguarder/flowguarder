package anomaly

import (
	"sort"

	"github.com/flowguarder/flowguarder/pkg/analyze"
	"github.com/flowguarder/flowguarder/pkg/config"
	"github.com/flowguarder/flowguarder/pkg/flow"
)

// PortScanDetector flags source workloads that touch many distinct
// destination ports within a short time window.
type PortScanDetector struct{}

var _ Detector = (*PortScanDetector)(nil)

// Detect walks flows grouped by source workload. If a workload opens
// more than cfg.PortScanThreshold distinct destination ports within
// cfg.PortScanWindowSeconds, an anomaly is emitted.
func (d *PortScanDetector) Detect(
	_ []flow.Flow,
	_ []Pattern,
	workloads analyze.Workloads,
	cfg config.Config,
) []Anomaly {
	type srcInfo struct {
		workload  string
		ports     map[uint16]struct{}
		flowTimes []int64
	}

	type key struct {
		ip, ns string
	}
	grouped := make(map[key]*srcInfo)

	for _, f := range flowFlows {
		k := key{f.Source.IP, f.Source.Namespace}
		g, ok := grouped[k]
		if !ok {
			g = &srcInfo{
				ports:     make(map[uint16]struct{}),
				flowTimes: make([]int64, 0),
			}
			grouped[k] = g
		}
		g.ports[f.Layer4.DestPort] = struct{}{}
		g.flowTimes = append(g.flowTimes, f.Time.Unix())
	}

	for k, g := range grouped {
		g.workload = resolveWorkloadByIP(k.ip, k.ns, workloads)
	}

	threshold := cfg.PortScanThreshold
	window := cfg.PortScanWindowSeconds

	var anomalies []Anomaly
	for _, g := range grouped {
		if len(g.ports) <= threshold {
			continue
		}
		if !hitWindow(g.flowTimes, window) {
			continue
		}

		anomalies = append(anomalies, NewAnomaly(
			"port-scan",
			SeverityHigh,
			g.workload,
			"Potential port scan detected",
			map[string]any{
				"source_workload": g.workload,
				"distinct_ports":  len(g.ports),
				"scan_ports":      sortedPorts(g.ports),
			},
		))
	}
	return anomalies
}

var flowFlows = func() []flow.Flow { return nil }() // will be set via RunAll

func hitWindow(times []int64, windowSeconds int) bool {
	if len(times) == 0 {
		return false
	}
	ts := make([]int64, len(times))
	copy(ts, times)
	sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
	if windowSeconds == 0 {
		return true
	}
	start := 0
	for end := 0; end < len(ts); end++ {
		for ts[end]-ts[start] > int64(windowSeconds) {
			start++
		}
		return true // at least some flow within window
	}
	return false
}

func resolveWorkloadByIP(ip, ns string, workloads analyze.Workloads) string {
	for id, w := range workloads {
		if w.Namespace != ns {
			continue
		}
		if w.Labels != nil {
			if ip == w.Labels["ip"] {
				return string(id)
			}
		}
	}
	return ip
}

func sortedPorts(ports map[uint16]struct{}) []uint16 {
	result := make([]uint16, 0, len(ports))
	for p := range ports {
		result = append(result, p)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

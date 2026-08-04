package anomaly

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/flowguarder/flowguarder/pkg/analyze"
	"github.com/flowguarder/flowguarder/pkg/config"
	"github.com/flowguarder/flowguarder/pkg/flow"
)

func TestAsymmetricDetector(t *testing.T) {
	t.Parallel()

	flowWithBytes := func(srcNS, srcIP, dstNS, dstIP, srcLabelKey, srcLabelVal string, dir flow.Direction, bytes uint64) flow.Flow {
		ep := flow.Endpoint{Namespace: srcNS, IP: srcIP}
		if srcLabelKey != "" {
			ep.Labels = map[string]string{srcLabelKey: srcLabelVal}
		}
		return flow.Flow{
			Source:      ep,
			Destination: flow.Endpoint{Namespace: dstNS, IP: dstIP},
			Direction:   dir,
			Verdict:     flow.Forwarded,
			Bytes:       bytes,
			Time:        time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		}
	}

	tests := []struct {
		name        string
		flows       []flow.Flow
		workloads   analyze.Workloads
		cfg         config.Config
		expectCount int
	}{
		{
			name: "bytes-based flag: egress=2000 ingress=100 ratio=20 at threshold 10",
			flows: []flow.Flow{
				flowWithBytes("app", "10.0.0.1", "ext", "8.8.8.8", "app", "web", flow.Egress, 2000),
				flowWithBytes("ext", "8.8.8.8", "app", "10.0.0.1", "app", "web", flow.Ingress, 100),
			},
			workloads: analyze.Workloads{
				"app/web": {
					Name: "web", Namespace: "app",
					Labels: map[string]string{"app": "web"},
				},
			},
			expectCount: 1,
		},
		{
			name: "equal bytes not flagged",
			flows: []flow.Flow{
				flowWithBytes("app", "10.0.0.1", "ext", "8.8.8.8", "app", "web", flow.Egress, 1000),
				flowWithBytes("app", "10.0.0.1", "ext", "8.8.8.8", "app", "web", flow.Ingress, 1000),
			},
			workloads: analyze.Workloads{
				"app/web": {
					Name: "web", Namespace: "app",
					Labels: map[string]string{"app": "web"},
				},
			},
			expectCount: 0,
		},
		{
			name: "controller-like workload gpu-operator skipped",
			flows: []flow.Flow{
				flowWithBytes("gpu-operator", "10.0.0.1", "ext", "8.8.8.8", "app", "gpu-node", flow.Egress, 5000),
			},
			workloads: analyze.Workloads{
				"gpu-operator/gpu-node": {
					Name: "gpu-node", Namespace: "gpu-operator",
					Labels: map[string]string{"app": "gpu-node"},
					Kind:  analyze.Unknown,
				},
			},
			expectCount: 0,
		},
		{
			name: "CronJob-labeled workload skipped",
			flows: []flow.Flow{
				flowWithBytes("batch", "10.0.0.1", "ext", "8.8.8.8", "app", "my-cron", flow.Egress, 5000),
			},
			workloads: analyze.Workloads{
				"batch/my-cron": {
					Name: "my-cron", Namespace: "batch",
					Labels: map[string]string{"app": "my-cron", "job-name": "my-cron-job"},
					Kind:  analyze.CronJob,
				},
			},
			expectCount: 0,
		},
		{
			name: "custom AsymmetricRatio=50 low threshold flags",
			flows: []flow.Flow{
				flowWithBytes("app", "10.0.0.1", "ext", "8.8.8.8", "app", "web", flow.Egress, 500),
			},
			workloads: analyze.Workloads{
				"app/web": {Name: "web", Namespace: "app", Labels: map[string]string{"app": "web"}},
			},
			cfg:         config.Config{AsymmetricRatio: 50.0},
			expectCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := AsymmetricDetector{}
			anomalies := d.Detect(tt.flows, nil, tt.workloads, tt.cfg)
			require.Len(t, anomalies, tt.expectCount)
		})
	}
}

func TestAsymmetricDetectorBytes(t *testing.T) {
	t.Parallel()

	// Specific bytes-based ratio test: egress_bytes=2000, ingress_bytes=100, ratio=20 >= threshold 10.
	d := AsymmetricDetector{}
	anomalies := d.Detect([]flow.Flow{
		{
			Source:      flow.Endpoint{Namespace: "app", IP: "10.0.0.1"},
			Destination: flow.Endpoint{Namespace: "ext", IP: "8.8.8.8"},
			Direction:   flow.Egress,
			Verdict:     flow.Forwarded,
			Bytes:       2000,
			Time:        time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			Source:      flow.Endpoint{Namespace: "ext", IP: "8.8.8.8"},
			Destination: flow.Endpoint{Namespace: "app", IP: "10.0.0.1"},
			Direction:   flow.Ingress,
			Verdict:     flow.Forwarded,
			Bytes:       100,
			Time:        time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}, nil, analyze.Workloads{}, config.Config{})

	require.Len(t, anomalies, 1)
	a := anomalies[0]
	require.Equal(t, "asymmetric-traffic", a.Type)
	require.Equal(t, "10.0.0.1", a.Workload)
	ratio, ok := a.Evidence["ratio"].(float64)
	require.True(t, ok)
	require.GreaterOrEqual(t, ratio, 10.0)
}

func TestAsymmetricEqualBytes(t *testing.T) {
	t.Parallel()

	d := AsymmetricDetector{}
	anomalies := d.Detect([]flow.Flow{
		{
			Source:      flow.Endpoint{Namespace: "app", IP: "10.0.0.1", Labels: map[string]string{"app": "web"}},
			Destination: flow.Endpoint{Namespace: "ext", IP: "8.8.8.8"},
			Direction:   flow.Egress,
			Verdict:     flow.Forwarded,
			Bytes:       1000,
			Time:        time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			Source:      flow.Endpoint{Namespace: "app", IP: "10.0.0.1", Labels: map[string]string{"app": "web"}},
			Destination: flow.Endpoint{Namespace: "ext", IP: "8.8.8.8"},
			Direction:   flow.Ingress,
			Verdict:     flow.Forwarded,
			Bytes:       1000,
			Time:        time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}, nil, analyze.Workloads{
		"app/web": {Name: "web", Namespace: "app", Labels: map[string]string{"app": "web"}},
	}, config.Config{})

	require.Len(t, anomalies, 0)
}

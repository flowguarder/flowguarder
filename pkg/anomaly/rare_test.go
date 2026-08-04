package anomaly

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/flowguarder/flowguarder/pkg/analyze"
	"github.com/flowguarder/flowguarder/pkg/config"
	"github.com/flowguarder/flowguarder/pkg/flow"
)

func TestRareFlowDetector(t *testing.T) {
	t.Parallel()

	emptyWorkloads := analyze.Workloads{}
	emptyFlows := []flow.Flow{}

	tests := []struct {
		name        string
		patterns    []Pattern
		expectCount int
		checkFlag   func(t *testing.T, a Anomaly)
	}{
		{
			name: "count<10 AND ratio<0.001 -> flagged",
			patterns: func() []Pattern {
				// One small rare pattern + many high-count fillers so the ratio drops below 0.001.
				p := []Pattern{
					{SrcWorkloadID: "ns/app", DstWorkloadID: "ns/api", Port: 8080, Protocol: "TCP", Count: 3, Bytes: 100},
				}
				for i := 0; i < 100; i++ {
					p = append(p, Pattern{
						SrcWorkloadID: "filler/w" + strconv.Itoa(i),
						DstWorkloadID: "ns/svc",
						Port:          uint16(1000 + i),
						Protocol:      "TCP",
						Count:         1000,
						Bytes:         1000,
					})
				}
				return p
			}(),
			expectCount: 1,
			checkFlag: func(t *testing.T, a Anomaly) {
				require.Equal(t, "rare-flow", a.Type)
				require.Equal(t, "ns/app", a.Workload)
			},
		},
		{
			name: "count>=10 not flagged regardless of ratio",
			patterns: []Pattern{
				{
					SrcWorkloadID:  "ns/app",
					DstWorkloadID:  "ns/api",
					Port:           8080,
					Protocol:       "TCP",
					Count:          10, // >= 10
					Bytes:          200,
				},
			},
			expectCount: 0,
		},
		{
			name: "workload with >20 patterns skipped entirely",
			patterns: func() []Pattern {
				p := make([]Pattern, 0, 25)
				for i := 0; i < 25; i++ {
					p = append(p, Pattern{
						SrcWorkloadID:  "scraper/scrape-bot",
						DstWorkloadID:  "ns/service",
						Port:           80 + uint16(i),
						Protocol:       "TCP",
						Count:          1,
						Bytes:          10,
					})
				}
				return p
			}(),
			expectCount: 0,
		},
		{
			name: "workload with <=20 patterns can produce flagged anomalies",
			patterns: func() []Pattern {
				p := make([]Pattern, 0, 120)
				for i := 0; i < 20; i++ {
					p = append(p, Pattern{
						SrcWorkloadID:  "ns/app",
						DstWorkloadID:  "ns/service",
						Port:           80 + uint16(i),
						Protocol:       "TCP",
						Count:          1,
						Bytes:          10,
					})
				}
				// Add 100 high-count filler patterns from other workloads so ratios drop below 0.001.
				for i := 0; i < 100; i++ {
					p = append(p, Pattern{
						SrcWorkloadID: "filler/w" + strconv.Itoa(i),
						DstWorkloadID: "ns/svc",
						Port:          uint16(2000 + i),
						Protocol:      "TCP",
						Count:         1000,
						Bytes:         1000,
					})
				}
				return p
			}(),
			expectCount: 20, // all 20 ns/app patterns are rare with count=1 and ratio < 0.001
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := RareFlowDetector{}
			anomalies := d.Detect(emptyFlows, tt.patterns, emptyWorkloads, config.Default())
			require.Len(t, anomalies, tt.expectCount)
			if tt.expectCount > 0 && len(anomalies) > 0 && tt.checkFlag != nil {
				tt.checkFlag(t, anomalies[0])
			}
		})
	}
}

func TestRareFlowDetectorNoPatterns(t *testing.T) {
	t.Parallel()

	d := RareFlowDetector{}
	anomalies := d.Detect(nil, nil, analyze.Workloads{}, config.Default())
	require.Len(t, anomalies, 0)
}

func TestRareFlowDetectorEmptyConfig(t *testing.T) {
	t.Parallel()

	// Default() has RareFlowThreshold=0.001. Build a pattern set with one rare
	// pattern and many high-count fillers so the ratio drops below 0.001.
	patterns := []Pattern{
		{SrcWorkloadID: "ns/app", DstWorkloadID: "ns/api", Port: 8080, Protocol: "TCP", Count: 2, Bytes: 50},
	}
	for i := 0; i < 100; i++ {
		patterns = append(patterns, Pattern{
			SrcWorkloadID: "filler/w" + strconv.Itoa(i),
			DstWorkloadID: "ns/svc",
			Port:          uint16(3000 + i),
			Protocol:      "TCP",
			Count:         1000,
			Bytes:         1000,
		})
	}

	cfg := config.Default()
	require.Equal(t, 0.001, cfg.RareFlowThreshold)

	d := RareFlowDetector{}
	anomalies := d.Detect(nil, patterns, analyze.Workloads{}, cfg)

	require.Len(t, anomalies, 1)
	require.Equal(t, "rare-flow", anomalies[0].Type)
}

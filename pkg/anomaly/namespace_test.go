package anomaly

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/flowguarder/flowguarder/pkg/analyze"
	"github.com/flowguarder/flowguarder/pkg/config"
	"github.com/flowguarder/flowguarder/pkg/flow"
)

func TestNamespaceDetector(t *testing.T) {
	t.Parallel()

	flowBase := func(srcNS, dstNS string, srcIP, dstIP string) flow.Flow {
		return flow.Flow{
			Source: flow.Endpoint{
				Namespace: srcNS,
				IP:        srcIP,
			},
			Destination: flow.Endpoint{
				Namespace: dstNS,
				IP:        dstIP,
			},
			Direction: flow.Egress,
			Verdict:   flow.Forwarded,
		}
	}

	emptyWorkloads := analyze.Workloads{}

	tests := []struct {
		name          string
		flows         []flow.Flow
		cfg           config.Config
		workloads     analyze.Workloads
		expectCount   int
		checkSeverity Severity
		checkEvidence func(t *testing.T, a Anomaly)
	}{
		{
			name: "allowlist src has dst not in allowlist -> flagged",
			flows: []flow.Flow{
				flowBase("front", "back", "10.0.0.1", "10.0.0.2"),
				flowBase("front", "back", "10.0.0.1", "10.0.0.3"),
			},
			cfg: config.Config{
				AllowedNamespacePairs: map[string][]string{
					"front": {"monitoring", "kube-system"},
				},
			},
			expectCount:  1,
			checkSeverity: SeverityMedium,
			checkEvidence: func(t *testing.T, a Anomaly) {
				require.Contains(t, a.Evidence, "pair")
				require.Equal(t, "front→back", a.Evidence["pair"])
				require.Equal(t, 2, a.Evidence["flow_count"])
			},
		},
		{
			name: "allowlist src allows dst -> no anomaly",
			flows: []flow.Flow{
				flowBase("front", "monitoring", "10.0.0.1", "10.0.0.2"),
			},
			cfg: config.Config{
				AllowedNamespacePairs: map[string][]string{
					"front": {"monitoring"},
				},
			},
			expectCount: 0,
		},
		{
			name: "src not in allowlist map -> flagged",
			flows: []flow.Flow{
				flowBase("db", "front", "10.0.0.1", "10.0.0.2"),
			},
			cfg: config.Config{
				AllowedNamespacePairs: map[string][]string{
					"front": {"monitoring"},
				},
			},
			expectCount: 1,
		},
		{
			name: "same namespace -> skipped",
			flows: []flow.Flow{
				flowBase("front", "front", "10.0.0.1", "10.0.0.2"),
			},
			expectCount: 0,
		},
		{
			name: "synthetic srcNS dash -> skipped",
			flows: []flow.Flow{
				{
					Source: flow.Endpoint{Namespace: "-"},
					Destination: flow.Endpoint{
						Namespace: "back",
						IP:        "10.0.0.2",
					},
					Direction: flow.Egress,
					Verdict:   flow.Forwarded,
				},
			},
			expectCount: 0,
		},
		{
			name: "synthetic dstNS dash -> skipped",
			flows: []flow.Flow{
				{
					Source: flow.Endpoint{
						Namespace: "front",
						IP:        "10.0.0.1",
					},
					Destination: flow.Endpoint{Namespace: "-"},
					Direction:   flow.Egress,
					Verdict:     flow.Forwarded,
				},
			},
			expectCount: 0,
		},
		{
			name: "synthetic srcNS empty -> skipped",
			flows: []flow.Flow{
				{
					Source: flow.Endpoint{Namespace: ""},
					Destination: flow.Endpoint{
						Namespace: "back",
						IP:        "10.0.0.2",
					},
					Direction: flow.Egress,
					Verdict:   flow.Forwarded,
				},
			},
			expectCount: 0,
		},
		{
			name: "external/ip representation when workload missing",
			flows: []flow.Flow{
				flowBase("ext-ns", "app-ns", "203.0.113.5", "10.0.0.2"),
			},
			cfg:           config.Config{},
			workloads:     emptyWorkloads,
			expectCount:   1,
			checkSeverity: SeverityLow,
			checkEvidence: func(t *testing.T, a Anomaly) {
				require.Equal(t, "external/203.0.113.5", a.Evidence["representative_src"])
			},
		},
		{
			name: "empty config severity low with config_note",
			flows: []flow.Flow{
				flowBase("front", "back", "10.0.0.1", "10.0.0.2"),
			},
			cfg:           config.Config{},
			expectCount:   1,
			checkSeverity: SeverityLow,
			checkEvidence: func(t *testing.T, a Anomaly) {
				require.Equal(t, "no allowed_namespace_pairs configured; cross-namespace pairs are informational only", a.Evidence["config_note"])
			},
		},
		{
			name: "non-empty config keeps medium no config_note",
			flows: []flow.Flow{
				flowBase("front", "back", "10.0.0.1", "10.0.0.2"),
				flowBase("front", "back", "10.0.0.1", "10.0.0.3"),
			},
			cfg: config.Config{
				AllowedNamespacePairs: map[string][]string{
					"front": {"monitoring"},
				},
			},
			expectCount: 1,
			checkEvidence: func(t *testing.T, a Anomaly) {
				_, hasConfigNote := a.Evidence["config_note"]
				require.False(t, hasConfigNote)
				require.Equal(t, SeverityMedium, a.Severity)
				require.Equal(t, 2, a.Evidence["flow_count"])
			},
		},
		{
			name: "multiple flows same pair grouped",
			flows: []flow.Flow{
				flowBase("front", "back", "10.0.0.1", "10.0.0.2"),
				flowBase("front", "back", "10.0.0.1", "10.0.0.3"),
				flowBase("front", "back", "10.0.0.1", "10.0.0.4"),
			},
			expectCount: 1,
			checkEvidence: func(t *testing.T, a Anomaly) {
				require.Equal(t, 3, a.Evidence["flow_count"])
			},
		},
		{
			name: "no cross-namespace flows -> nil",
			flows: []flow.Flow{
				flowBase("front", "front", "10.0.0.1", "10.0.0.2"),
			},
			expectCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := NamespaceDetector{}
			anomalies := d.Detect(tt.flows, nil, tt.workloads, tt.cfg)
			require.Len(t, anomalies, tt.expectCount)
			if tt.expectCount > 0 && len(anomalies) > 0 {
				if tt.checkSeverity != "" {
					require.Equal(t, tt.checkSeverity, anomalies[0].Severity)
				}
				if tt.checkEvidence != nil {
					tt.checkEvidence(t, anomalies[0])
				}
			}
		})
	}
}

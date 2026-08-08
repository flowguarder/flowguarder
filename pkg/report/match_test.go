package report

import (
	"testing"
	"time"

	"github.com/flowguarder/flowguarder/pkg/analyze"
	"github.com/flowguarder/flowguarder/pkg/flow"
	"github.com/flowguarder/flowguarder/pkg/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- MatchFlow tests ----

func TestMatchFlow_NoPolicies(t *testing.T) {
	t.Parallel()

	f := makeTestFlow(flow.Egress, "10.0.0.1", "10.0.0.2", 8080, "TCP", flow.Forwarded)
	assert.False(t, MatchFlow(f, nil))
	assert.False(t, MatchFlow(f, []policy.Policy{}))
}

func TestMatchFlow_EgressPortMatch(t *testing.T) {
	t.Parallel()

	// Egress flow: frontend → backend:8080
	f := makeTestFlow(flow.Egress, "10.0.0.1", "10.0.0.2", 8080, "TCP", flow.Forwarded)

	policies := []policy.Policy{
		{
			WorkloadID:   "default/frontend",
			WorkloadName: "frontend",
			EgressRules: []policy.EgressRule{
				{
					ToWorkloads: []string{"default/backend"},
					ToPorts:     []policy.PortSpec{{Port: 8080, Protocol: "TCP"}},
				},
			},
		},
	}

	assert.True(t, MatchFlow(f, policies), "flow should match egress policy")
}

func TestMatchFlow_EgressNoMatch(t *testing.T) {
	t.Parallel()

	f := makeTestFlow(flow.Egress, "10.0.0.1", "10.0.0.2", 9090, "TCP", flow.Forwarded)

	policies := []policy.Policy{
		{
			WorkloadID: "default/frontend",
			EgressRules: []policy.EgressRule{
				{
					ToWorkloads: []string{"default/backend"},
					ToPorts:     []policy.PortSpec{{Port: 8080, Protocol: "TCP"}},
				},
			},
		},
	}

	assert.False(t, MatchFlow(f, policies), "flow on non-matching port should not match")
}

func TestMatchFlow_IngressPortMatch(t *testing.T) {
	t.Parallel()

	// Ingress flow: frontend → backend:8080
	f := makeTestFlow(flow.Ingress, "10.0.0.1", "10.0.0.2", 8080, "TCP", flow.Forwarded)

	policies := []policy.Policy{
		{
			WorkloadID: "default/backend",
			IngressRules: []policy.IngressRule{
				{
					FromWorkloads: []string{"default/frontend"},
					Ports:         []policy.PortSpec{{Port: 8080, Protocol: "TCP"}},
				},
			},
		},
	}

	assert.True(t, MatchFlow(f, policies), "flow should match ingress policy")
}

func TestMatchFlow_InternalFlow(t *testing.T) {
	t.Parallel()

	f := makeTestFlow(flow.Internal, "10.0.0.1", "10.0.0.2", 80, "TCP", flow.Forwarded)

	policies := []policy.Policy{
		{
			WorkloadID: "default/backend",
			IngressRules: []policy.IngressRule{
				{
					FromWorkloads: []string{"default/frontend"},
					Ports:         []policy.PortSpec{{Port: 80, Protocol: "TCP"}},
				},
			},
		},
	}

	assert.True(t, MatchFlow(f, policies), "internal flow should match dest ingress policy")
}

func TestMatchFlow_WorldEgressPortOnlyRule(t *testing.T) {
	t.Parallel()

	f := makeTestFlow(flow.Egress, "10.0.0.1", "203.0.113.50", 443, "TCP", flow.Forwarded)
	f.PeerType = flow.EgressWorld

	policies := []policy.Policy{
		{
			WorkloadID: "default/frontend", // matches flow's source
			EgressRules: []policy.EgressRule{
				{
					ToPorts: []policy.PortSpec{{Port: 443, Protocol: "TCP"}},
					// No ToWorkloads or ToCIDRs — port-only rule matches any.
				},
			},
		},
	}

	assert.True(t, MatchFlow(f, policies), "port-only egress rule should match any destination")
}

func TestMatchFlow_CIDRMatchWorld(t *testing.T) {
	t.Parallel()

	f := makeTestFlow(flow.Egress, "10.0.0.1", "203.0.113.50", 443, "TCP", flow.Forwarded)
	f.PeerType = flow.EgressWorld

	policies := []policy.Policy{
		{
			WorkloadID: "default/frontend",
			EgressRules: []policy.EgressRule{
				{
					ToCIDRs: []string{"0.0.0.0/0"},
					ToPorts: []policy.PortSpec{{Port: 443, Protocol: "TCP"}},
				},
			},
		},
	}

	assert.True(t, MatchFlow(f, policies), "0.0.0.0/0 CIDR should match any world destination")
}

func TestMatchFlow_CIDRMatchApiserver(t *testing.T) {
	t.Parallel()

	// Egress flow to apiserver (port 6443, PeerType=KubeAPIServer)
	f := flow.Flow{
		Direction: flow.Egress,
		Source: flow.Endpoint{
			Namespace: "default",
			PodName:   "frontend",
			Labels:    map[string]string{"app": "frontend"},
			IP:        "10.0.0.1",
		},
		Destination: flow.Endpoint{
			Namespace: "default",
			PodName:   "apiserver",
			Labels:    map[string]string{"app": "apiserver"},
			IP:        "10.96.0.1",
		},
		Layer4:   flow.Layer4{DestPort: 6443, Protocol: flow.TCP},
		Verdict:  flow.Forwarded,
		PeerType: flow.KubeAPIServer,
	}

	policies := []policy.Policy{
		{
			WorkloadID: "default/frontend",
			EgressRules: []policy.EgressRule{
				{
					ToCIDRs: []string{"apiserver"},
					ToPorts: []policy.PortSpec{{Port: 6443, Protocol: "TCP"}},
				},
			},
		},
	}

	assert.True(t, MatchFlow(f, policies), "apiserver CIDR should match")
}

func TestMatchFlow_WrongWorkload(t *testing.T) {
	t.Parallel()

	// Egress flow: frontend → backend, but policy is on backend's workload
	f := makeTestFlow(flow.Egress, "10.0.0.1", "10.0.0.2", 8080, "TCP", flow.Forwarded)

	policies := []policy.Policy{
		{
			WorkloadID: "default/backend",
			IngressRules: []policy.IngressRule{
				{
					FromWorkloads: []string{"default/frontend"},
					Ports:         []policy.PortSpec{{Port: 8080, Protocol: "TCP"}},
				},
			},
		},
	}

	// Egress flows check source workload — backend policy doesn't cover frontend's egress.
	assert.False(t, MatchFlow(f, policies), "egress flow should not match dest workload policy")
}

// ---- ComputeCoverage tests ----

func TestComputeCoverage_AllCovered(t *testing.T) {
	t.Parallel()

	f := makeTestFlow(flow.Egress, "10.0.0.1", "10.0.0.2", 8080, "TCP", flow.Forwarded)
	f.Bytes = 1000

	policies := []policy.Policy{
		{
			WorkloadID: "default/frontend",
			EgressRules: []policy.EgressRule{
				{
					ToWorkloads: []string{"default/backend"},
					ToPorts:     []policy.PortSpec{{Port: 8080, Protocol: "TCP"}},
				},
			},
		},
	}

	result := ComputeCoverage([]flow.Flow{f}, policies)
	assert.Equal(t, 1, result.TotalFlows)
	assert.Equal(t, 1, result.CoveredFlows)
	assert.Equal(t, uint64(1000), result.TotalBytes)
	assert.Equal(t, uint64(1000), result.CoveredBytes)
	assert.InDelta(t, 100.0, result.FlowPercent, 0.01)
	assert.InDelta(t, 100.0, result.BytePercent, 0.01)
}

func TestComputeCoverage_NoneCovered(t *testing.T) {
	t.Parallel()

	f := makeTestFlow(flow.Egress, "10.0.0.1", "10.0.0.2", 8080, "TCP", flow.Forwarded)
	f.Bytes = 500

	policies := []policy.Policy{
		{
			WorkloadID: "default/other",
		},
	}

	result := ComputeCoverage([]flow.Flow{f}, policies)
	assert.Equal(t, 1, result.TotalFlows)
	assert.Equal(t, 0, result.CoveredFlows)
	assert.InDelta(t, 0.0, result.FlowPercent, 0.01)
}

func TestComputeCoverage_PartialCoverage(t *testing.T) {
	t.Parallel()

	f1 := makeTestFlow(flow.Egress, "10.0.0.1", "10.0.0.2", 8080, "TCP", flow.Forwarded)
	f1.Bytes = 1000
	f2 := makeTestFlow(flow.Egress, "10.0.0.1", "10.0.0.2", 9090, "TCP", flow.Forwarded)
	f2.Bytes = 500

	policies := []policy.Policy{
		{
			WorkloadID: "default/frontend",
			EgressRules: []policy.EgressRule{
				{
					ToWorkloads: []string{"default/backend"},
					ToPorts:     []policy.PortSpec{{Port: 8080, Protocol: "TCP"}},
				},
			},
		},
	}

	result := ComputeCoverage([]flow.Flow{f1, f2}, policies)
	assert.Equal(t, 2, result.TotalFlows)
	assert.Equal(t, 1, result.CoveredFlows)
	assert.InDelta(t, 50.0, result.FlowPercent, 0.01)
	assert.InDelta(t, 66.67, result.BytePercent, 0.01) // 1000 / 1500
}

func TestComputeCoverage_EmptyFlows(t *testing.T) {
	t.Parallel()

	result := ComputeCoverage([]flow.Flow{}, []policy.Policy{})
	assert.Equal(t, 0, result.TotalFlows)
	assert.Equal(t, 0, result.CoveredFlows)
}

// ---- UncoveredFlows tests ----

func TestUncoveredFlows_AllCovered(t *testing.T) {
	t.Parallel()

	f := makeTestFlow(flow.Egress, "10.0.0.1", "10.0.0.2", 80, "TCP", flow.Forwarded)

	policies := []policy.Policy{
		{
			WorkloadID: "default/frontend",
			EgressRules: []policy.EgressRule{
				{
					ToWorkloads: []string{"default/backend"},
					ToPorts:     []policy.PortSpec{{Port: 80, Protocol: "TCP"}},
				},
			},
		},
	}

	uncovered := UncoveredFlows([]flow.Flow{f}, policies)
	require.Empty(t, uncovered)
}

func TestUncoveredFlows_NoneCovered(t *testing.T) {
	t.Parallel()

	f1 := makeTestFlow(flow.Egress, "10.0.0.1", "10.0.0.2", 80, "TCP", flow.Forwarded)
	f2 := makeTestFlow(flow.Egress, "10.0.0.3", "10.0.0.4", 443, "TCP", flow.Forwarded)

	policies := []policy.Policy{}

	uncovered := UncoveredFlows([]flow.Flow{f1, f2}, policies)
	require.Len(t, uncovered, 2)
}

func TestUncoveredFlows_PartialCoverage(t *testing.T) {
	t.Parallel()

	f1 := makeTestFlow(flow.Egress, "10.0.0.1", "10.0.0.2", 80, "TCP", flow.Forwarded)
	f2 := makeTestFlow(flow.Egress, "10.0.0.3", "10.0.0.4", 443, "TCP", flow.Forwarded)
	f3 := makeTestFlow(flow.Egress, "10.0.0.5", "10.0.0.6", 3000, "TCP", flow.Forwarded)

	policies := []policy.Policy{
		{
			WorkloadID: "default/frontend",
			EgressRules: []policy.EgressRule{
				{
					ToPorts: []policy.PortSpec{{Port: 80, Protocol: "TCP"}},
				},
			},
		},
	}

	uncovered := UncoveredFlows([]flow.Flow{f1, f2, f3}, policies)
	require.Len(t, uncovered, 2, "only f2 and f3 should be uncovered")
}

func TestUncoveredFlows_NilInput(t *testing.T) {
	t.Parallel()

	result := UncoveredFlows(nil, nil)
	assert.NotNil(t, result)
	require.Empty(t, result)
}

// ---- Helper ----

func makeTestFlow(dir flow.Direction, srcIP, dstIP string, port uint16, proto string, verdict flow.Verdict) flow.Flow {
	return flow.Flow{
		Direction: dir,
		Source: flow.Endpoint{
			Namespace: "default",
			PodName:   "frontend",
			Labels:    map[string]string{"app": "frontend"},
			IP:        srcIP,
		},
		Destination: flow.Endpoint{
			Namespace: "default",
			PodName:   "backend",
			Labels:    map[string]string{"app": "backend"},
			IP:        dstIP,
		},
		Layer4:  flow.Layer4{DestPort: port, Protocol: flow.Protocol(proto)},
		Verdict: verdict,
	}
}

// ---- Top-level function coverage ----

func TestTopFlows_FunctionExists(t *testing.T) {
	t.Parallel()
	_ = TopFlows
}

func TestEgressWorldFlows_FunctionExists(t *testing.T) {
	t.Parallel()
	_ = EgressWorldFlows
}

func TestDroppedFlows_FunctionExists(t *testing.T) {
	t.Parallel()
	_ = DroppedFlows
}

func BenchmarkMatchFlow_Egress(b *testing.B) {
	f := makeTestFlow(flow.Egress, "10.0.0.1", "10.0.0.2", 8080, "TCP", flow.Forwarded)
	policies := []policy.Policy{
		{
			WorkloadID: "default/frontend",
			EgressRules: []policy.EgressRule{
				{
					ToWorkloads: []string{"default/backend"},
					ToPorts:     []policy.PortSpec{{Port: 8080, Protocol: "TCP"}},
				},
			},
		},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = MatchFlow(f, policies)
	}
}

func BenchmarkComputeCoverage(b *testing.B) {
	flows := make([]flow.Flow, 1000)
	for i := range flows {
		flows[i] = makeTestFlow(flow.Egress, "10.0.0.1", "10.0.0.2", 8080, "TCP", flow.Forwarded)
	}
	policies := []policy.Policy{
		{
			WorkloadID: "default/frontend",
			EgressRules: []policy.EgressRule{
				{
					ToWorkloads: []string{"default/backend"},
					ToPorts:     []policy.PortSpec{{Port: 8080, Protocol: "TCP"}},
				},
			},
		},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ComputeCoverage(flows, policies)
	}
}

func TestTopFlows_WorkloadsNotUsed(t *testing.T) {
	t.Parallel()

	// Verify that workloads parameter is accepted (even though unused)
	now := time.Now()
	flows := []flow.Flow{
		{
			Time:        now,
			Source:      flow.Endpoint{Namespace: "default", PodName: "a", Labels: map[string]string{"app": "a"}, IP: "10.0.0.1"},
			Destination: flow.Endpoint{Namespace: "default", PodName: "b", Labels: map[string]string{"app": "b"}, IP: "10.0.0.2"},
			Layer4:      flow.Layer4{DestPort: 80, Protocol: flow.TCP},
			Verdict:     flow.Forwarded,
			Direction:   flow.Egress,
			Bytes:       100,
		},
	}
	workloads := analyze.Aggregate(flows)
	result := TopFlows(flows, workloads, 5)
	require.Len(t, result, 1)
}

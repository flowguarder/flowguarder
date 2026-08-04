package report

import (
	"testing"
	"time"

	"github.com/flowguarder/flowguarder/pkg/analyze"
	"github.com/flowguarder/flowguarder/pkg/flow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTopFlows(t *testing.T) {
	t.Parallel()

	now := time.Now()
	flows := []flow.Flow{
		{
			Time:        now,
			Source:      flow.Endpoint{Namespace: "default", PodName: "frontend-abc", Labels: map[string]string{"app": "frontend"}, IP: "10.0.0.1"},
			Destination: flow.Endpoint{Namespace: "default", PodName: "backend-def", Labels: map[string]string{"app": "backend"}, IP: "10.0.0.2"},
			Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:     flow.Forwarded,
			Direction:   flow.Egress,
			PeerType:    flow.PodPod,
			Bytes:       5000,
		},
		{
			Time:        now,
			Source:      flow.Endpoint{Namespace: "default", PodName: "frontend-abc", Labels: map[string]string{"app": "frontend"}, IP: "10.0.0.1"},
			Destination: flow.Endpoint{Namespace: "default", PodName: "backend-def", Labels: map[string]string{"app": "backend"}, IP: "10.0.0.2"},
			Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:     flow.Forwarded,
			Direction:   flow.Egress,
			PeerType:    flow.PodPod,
			Bytes:       2000,
		},
		{
			Time:        now,
			Source:      flow.Endpoint{Namespace: "default", PodName: "frontend-abc", Labels: map[string]string{"app": "frontend"}, IP: "10.0.0.1"},
			Destination: flow.Endpoint{Namespace: "default", PodName: "postgres-ghi", Labels: map[string]string{"app": "postgres"}, IP: "10.0.0.3"},
			Layer4:      flow.Layer4{DestPort: 5432, Protocol: flow.TCP},
			Verdict:     flow.Forwarded,
			Direction:   flow.Egress,
			PeerType:    flow.PodPod,
			Bytes:       10000,
		},
	}

	workloads := analyze.Aggregate(flows)

	top := TopFlows(flows, workloads, 2)
	require.Len(t, top, 2)

	// Top 2: postgres (10000), frontend->backend (7000)
	assert.Equal(t, uint64(10000), top[0].Bytes, "first flow should have most bytes")
	assert.Equal(t, uint16(5432), top[0].Port)
	assert.Equal(t, "TCP", top[0].Proto)
	assert.Equal(t, 1, top[0].Count)

	assert.Equal(t, uint64(7000), top[1].Bytes, "second flow should have 7000 bytes")
	assert.Equal(t, uint16(8080), top[1].Port)
	assert.Equal(t, 2, top[1].Count)
}

func TestEgressWorldFlows(t *testing.T) {
	t.Parallel()

	now := time.Now()
	flows := []flow.Flow{
		{
			Time:        now,
			Source:      flow.Endpoint{Namespace: "default", PodName: "frontend-abc", Labels: map[string]string{"app": "frontend"}, IP: "10.0.0.1"},
			Destination: flow.Endpoint{Namespace: "", PodName: "", Labels: map[string]string{}, IP: "8.8.8.8"},
			Layer4:      flow.Layer4{DestPort: 443, Protocol: flow.TCP},
			Verdict:     flow.Forwarded,
			Direction:   flow.Egress,
			PeerType:    flow.PodPod,
			Bytes:       1000,
		},
		{
			Time:        now,
			Source:      flow.Endpoint{Namespace: "default", PodName: "worker-xyz", Labels: map[string]string{"app": "worker"}, IP: "10.0.0.2"},
			Destination: flow.Endpoint{Namespace: "", PodName: "api.google.com", Labels: map[string]string{}, IP: "142.250.80.46"},
			Layer4:      flow.Layer4{DestPort: 443, Protocol: flow.TCP},
			Verdict:     flow.Forwarded,
			Direction:   flow.Egress,
			PeerType:    flow.EgressWorld,
			Bytes:       3500,
		},
		{
			Time:        now,
			Source:      flow.Endpoint{Namespace: "default", PodName: "worker-xyz", Labels: map[string]string{"app": "worker"}, IP: "10.0.0.2"},
			Destination: flow.Endpoint{Namespace: "", PodName: "api.github.com", Labels: map[string]string{}, IP: "140.82.121.5"},
			Layer4:      flow.Layer4{DestPort: 443, Protocol: flow.TCP},
			Verdict:     flow.Forwarded,
			Direction:   flow.Egress,
			PeerType:    flow.EgressWorld,
			Bytes:       2000,
		},
	}

	workloads := analyze.Aggregate(flows)

	egressWorld := EgressWorldFlows(flows, workloads, 0)
	require.Len(t, egressWorld, 2)

	// Should only have egress-world flows, sorted by bytes desc
	assert.Equal(t, uint64(3500), egressWorld[0].Bytes)
	assert.Equal(t, uint64(2000), egressWorld[1].Bytes)

	// Verify src labels are preserved from the flow's source
	assert.Equal(t, "default/worker", egressWorld[0].Src)
	// Dst has no pod labels, so ResolveWorkload returns empty name -> ""
	assert.Contains(t, egressWorld[1].Dst, "api.github.com")
}

func TestDroppedFlows(t *testing.T) {
	t.Parallel()

	now := time.Now()
	flows := []flow.Flow{
		// Allowed flow 1
		{
			Time:        now,
			Source:      flow.Endpoint{Namespace: "default", PodName: "frontend-abc", Labels: map[string]string{"app": "frontend"}, IP: "10.0.0.1"},
			Destination: flow.Endpoint{Namespace: "default", PodName: "backend-def", Labels: map[string]string{"app": "backend"}, IP: "10.0.0.2"},
			Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:     flow.Forwarded,
			Direction:   flow.Egress,
			PeerType:    flow.PodPod,
			Bytes:       5000,
		},
		// Allowed flow 2
		{
			Time:        now,
			Source:      flow.Endpoint{Namespace: "default", PodName: "frontend-abc", Labels: map[string]string{"app": "frontend"}, IP: "10.0.0.1"},
			Destination: flow.Endpoint{Namespace: "default", PodName: "backend-def", Labels: map[string]string{"app": "backend"}, IP: "10.0.0.2"},
			Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
			PeerType:    flow.PodPod,
			Bytes:       3000,
		},
		// Dropped flow with PolicyName
		{
			Time:        now,
			Source:      flow.Endpoint{Namespace: "default", PodName: "frontend-abc", Labels: map[string]string{"app": "frontend"}, IP: "10.0.0.1"},
			Destination: flow.Endpoint{Namespace: "default", PodName: "backend-def", Labels: map[string]string{"app": "backend"}, IP: "10.0.0.2"},
			Layer4:      flow.Layer4{DestPort: 6379, Protocol: flow.TCP},
			Verdict:     flow.Dropped,
			Direction:   flow.Egress,
			PeerType:    flow.PodPod,
			Bytes:       200,
			PolicyName:  "deny-redis",
		},
	}

	workloads := analyze.Aggregate(flows)

	dropped := DroppedFlows(flows, workloads, 0)
	require.Len(t, dropped, 1)

	// Only drop flow
	assert.Equal(t, uint64(200), dropped[0].Bytes)
	assert.Equal(t, 1, dropped[0].Count)
	assert.Equal(t, "deny-redis", dropped[0].Policy)
}

func TestTopFlowsTiebreak(t *testing.T) {
	t.Parallel()

	now := time.Now()
	flows := []flow.Flow{
		{
			Time:        now,
			Source:      flow.Endpoint{Namespace: "ns-b", PodName: "alpha-pod", Labels: map[string]string{"app": "alpha"}, IP: "10.0.0.1"},
			Destination: flow.Endpoint{Namespace: "ns-a", PodName: "beta-pod", Labels: map[string]string{"app": "beta"}, IP: "10.0.0.2"},
			Layer4:      flow.Layer4{DestPort: 80, Protocol: flow.TCP},
			Verdict:     flow.Forwarded,
			Direction:   flow.Egress,
			PeerType:    flow.PodPod,
			Bytes:       5000,
		},
		{
			Time:        now,
			Source:      flow.Endpoint{Namespace: "ns-a", PodName: "beta-pod", Labels: map[string]string{"app": "beta"}, IP: "10.0.0.2"},
			Destination: flow.Endpoint{Namespace: "ns-b", PodName: "alpha-pod", Labels: map[string]string{"app": "alpha"}, IP: "10.0.0.1"},
			Layer4:      flow.Layer4{DestPort: 443, Protocol: flow.TCP},
			Verdict:     flow.Forwarded,
			Direction:   flow.Egress,
			PeerType:    flow.PodPod,
			Bytes:       5000,
		},
	}

	workloads := analyze.Aggregate(flows)

	// Run twice to confirm deterministic order
	result1 := TopFlows(flows, workloads, 0)
	result2 := TopFlows(flows, workloads, 0)
	assert.Equal(t, result1, result2, "TopFlows must be deterministic")

	// Both have equal bytes (5000) — tiebreak should be by (Src, Dst, Port, Proto)
	// ns-a/beta -> ns-b/alpha:443/TCP should come first (lower src: "ns-a" < "ns-b")
	require.Len(t, result1, 2)
	assert.Equal(t, "ns-a/beta", result1[0].Src, "tiebreak: lower Src should come first")
	assert.Equal(t, "ns-b/alpha", result1[1].Src)
}

func TestTopFlows_NegativeN(t *testing.T) {
	t.Parallel()

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

	all := TopFlows(flows, workloads, 0)
	require.Len(t, all, 1)

	neg := TopFlows(flows, workloads, -1)
	require.Len(t, neg, 1)
	assert.Equal(t, all, neg)
}

func TestDroppedFlows_PolicyFallback(t *testing.T) {
	t.Parallel()

	now := time.Now()
	flows := []flow.Flow{
		{
			Time:        now,
			Source:      flow.Endpoint{Namespace: "default", PodName: "client", Labels: map[string]string{"app": "client"}, IP: "10.0.0.1"},
			Destination: flow.Endpoint{Namespace: "default", PodName: "server", Labels: map[string]string{"app": "server"}, IP: "10.0.0.2"},
			Layer4:      flow.Layer4{DestPort: 3000, Protocol: flow.TCP},
			Verdict:     flow.Dropped,
			Direction:   flow.Egress,
			PeerType:    flow.PodPod,
			Bytes:       100,
			DropReason:  "policy denied",
		},
		{
			Time:        now,
			Source:      flow.Endpoint{Namespace: "default", PodName: "client", Labels: map[string]string{"app": "client"}, IP: "10.0.0.1"},
			Destination: flow.Endpoint{Namespace: "default", PodName: "server", Labels: map[string]string{"app": "server"}, IP: "10.0.0.2"},
			Layer4:      flow.Layer4{DestPort: 5000, Protocol: flow.TCP},
			Verdict:     flow.Dropped,
			Direction:   flow.Egress,
			PeerType:    flow.PodPod,
			Bytes:       200,
			PolicyName:  "deny-port-5000",
			DropReason:  "explicit deny",
		},
	}

	workloads := analyze.Aggregate(flows)

	dropped := DroppedFlows(flows, workloads, 0)
	require.Len(t, dropped, 2)

	// First by bytes desc: 200 > 100
	assert.Equal(t, uint64(200), dropped[0].Bytes)
	assert.Equal(t, "deny-port-5000", dropped[0].Policy, "should prefer PolicyName over DropReason")

	assert.Equal(t, uint64(100), dropped[1].Bytes)
	assert.Equal(t, "policy denied", dropped[1].Policy, "should fall back to DropReason when PolicyName is empty")
}

func TestTopFlows_NilInput(t *testing.T) {
	t.Parallel()

	result := TopFlows(nil, nil, 5)
	assert.NotNil(t, result) // should be a non-nil empty slice, not nil
	assert.Len(t, result, 0)
}

func TestEgressWorldFlows_NoMatches(t *testing.T) {
	t.Parallel()

	now := time.Now()
	flows := []flow.Flow{
		{
			Time:        now,
			Source:      flow.Endpoint{Namespace: "default", PodName: "a", Labels: map[string]string{"app": "a"}, IP: "10.0.0.1"},
			Destination: flow.Endpoint{Namespace: "default", PodName: "b", Labels: map[string]string{"app": "b"}, IP: "10.0.0.2"},
			Layer4:      flow.Layer4{DestPort: 80, Protocol: flow.TCP},
			Verdict:     flow.Forwarded,
			Direction:   flow.Egress,
			PeerType:    flow.PodPod,
			Bytes:       100,
		},
	}

	workloads := analyze.Aggregate(flows)

	result := EgressWorldFlows(flows, workloads, 0)
	assert.NotNil(t, result)
	assert.Len(t, result, 0)
}

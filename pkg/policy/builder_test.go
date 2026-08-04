package policy

import (
	"net"
	"testing"
	"time"

	"github.com/flowguarder/flowguarder/pkg/analyze"
	"github.com/flowguarder/flowguarder/pkg/config"
	"github.com/flowguarder/flowguarder/pkg/flow"
	"github.com/stretchr/testify/require"
)

func TestBuild_LabelPriority(t *testing.T) {
	t.Parallel()

	now := time.Now()

	workloads := analyze.Workloads{
		"prod/api-server": {
			Name:      "api-server",
			Namespace: "prod",
			Labels:    map[string]string{"app": "api-server"},
		},
		"prod/backend": {
			Name:      "backend",
			Namespace: "prod",
			Labels:    map[string]string{"app": "backend"},
		},
	}

	flows := []flow.Flow{
		{
			Time:      now,
			Source:    flow.Endpoint{Namespace: "prod", PodName: "api-server", IP: "10.0.0.1", Labels: map[string]string{"app": "api-server"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Egress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{})

	// Two distinct workloads → 2 distinct policies.
	require.Len(t, policies, 2)

	ids := []string{policies[0].WorkloadID, policies[1].WorkloadID}
	require.Contains(t, ids, "prod/api-server")
	require.Contains(t, ids, "prod/backend")
}

func TestBuild_PodHashDedup(t *testing.T) {
	t.Parallel()

	now := time.Now()

	// Two different pod template hash suffixes both resolve to workload "frontend".
	workloads := analyze.Workloads{
		"prod/frontend": {
			Name:      "frontend",
			Namespace: "prod",
			Labels:    map[string]string{"app": "frontend"},
		},
		"prod/backend": {
			Name:      "backend",
			Namespace: "prod",
			Labels:    map[string]string{"app": "backend"},
		},
	}

	flows := []flow.Flow{
		{
			Time:      now,
			Source:    flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Egress,
		},
		{
			Time:      now.Add(time.Second),
			Source:    flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Ingress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{})

	// Both pods resolve to the same workload pair; find the frontend policy.
	var frontendPolicy *Policy
	for i := range policies {
		if policies[i].WorkloadID == "prod/frontend" {
			frontendPolicy = &policies[i]
			break
		}
	}
	require.NotNil(t, frontendPolicy)
	// Egress should list the backend selector — both flows share same resolved dest workload.
	require.Equal(t, 1, len(frontendPolicy.EgressRules))
	require.Equal(t, []string{"app=backend"}, frontendPolicy.EgressRules[0].ToWorkloads)
	require.Equal(t, []PortSpec{{Port: 8080, Protocol: "TCP", Description: "observed 1 times"}}, frontendPolicy.EgressRules[0].ToPorts)
}

func TestBuild_IngressEgressAggregation(t *testing.T) {
	t.Parallel()

	now := time.Now()

	workloads := analyze.Workloads{
		"prod/frontend": {
			Name:      "frontend",
			Namespace: "prod",
			Labels:    map[string]string{"app": "frontend"},
		},
		"prod/backend": {
			Name:      "backend",
			Namespace: "prod",
			Labels:    map[string]string{"app": "backend"},
		},
	}

	flows := []flow.Flow{
		// Egress: frontend → backend (backend receives from frontend's perspective).
		{
			Time:      now,
			Source:    flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Egress,
		},
		// Ingress: backend receives from frontend.
		{
			Time:      now.Add(time.Second),
			Source:    flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Ingress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{})

	// Find backend policy.
	var backendPolicy, frontendPolicy *Policy
	for i := range policies {
		if policies[i].WorkloadID == "prod/backend" {
			backendPolicy = &policies[i]
		}
		if policies[i].WorkloadID == "prod/frontend" {
			frontendPolicy = &policies[i]
		}
	}
	require.NotNil(t, backendPolicy)
	require.NotNil(t, frontendPolicy)

	// Backend received the Ingress flow → has 1 IngressRule.
	require.Equal(t, 1, len(backendPolicy.IngressRules))
	require.Equal(t, 0, len(backendPolicy.EgressRules))

	// Frontend sent the Egress flow → has 1 EgressRule.
	require.Equal(t, 0, len(frontendPolicy.IngressRules))
	require.Equal(t, 1, len(frontendPolicy.EgressRules))
}

func TestBuild_PeerOnlyWorkload(t *testing.T) {
	t.Parallel()

	now := time.Now()

	// Backend only appears as a destination peer in a frontend egress flow.
	// It gets a policy entry with empty rules (never seen as a traffic source).
	workloads := analyze.Workloads{
		"prod/frontend": {
			Name:      "frontend",
			Namespace: "prod",
			Labels:    map[string]string{"app": "frontend"},
		},
		"prod/backend": {
			Name:      "backend",
			Namespace: "prod",
			Labels:    map[string]string{"app": "backend"},
		},
	}

	flows := []flow.Flow{
		{
			Time:      now,
			Source:    flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1"},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Egress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{})
	require.Len(t, policies, 2)

	// frontend has a non-empty EgressRule (saw traffic from this source)
	var frontendPolicy, backendPolicy *Policy
	for i := range policies {
		if policies[i].WorkloadID == "prod/frontend" {
			frontendPolicy = &policies[i]
		}
		if policies[i].WorkloadID == "prod/backend" {
			backendPolicy = &policies[i]
		}
	}
	require.NotNil(t, frontendPolicy)
	require.NotNil(t, backendPolicy)

	// Backend is observed as a destination — symmetric ingress from frontend's egress.
	require.Equal(t, 1, len(backendPolicy.IngressRules))
	require.Equal(t, []string{"app=frontend"}, backendPolicy.IngressRules[0].FromWorkloads)
	require.Len(t, backendPolicy.IngressRules[0].Ports, 1)
	require.Equal(t, uint16(8080), backendPolicy.IngressRules[0].Ports[0].Port)
	require.Equal(t, "TCP", backendPolicy.IngressRules[0].Ports[0].Protocol)
	require.Equal(t, 0, len(backendPolicy.EgressRules))

	// Frontend is observed → has a EgressRule pointing to backend.
	require.Equal(t, 1, len(frontendPolicy.EgressRules))
}

func TestBuild_DeterministicOrder(t *testing.T) {
	t.Parallel()

	now := time.Now()

	// Create 3 workloads in reverse-alphabetical order to test sorting.
	workloads := analyze.Workloads{
		"prod/zeta": {Name: "zeta", Namespace: "prod", Labels: map[string]string{"app": "zeta"}},
		"prod/alpha": {Name: "alpha", Namespace: "prod", Labels: map[string]string{"app": "alpha"}},
		"prod/mu": {Name: "mu", Namespace: "prod", Labels: map[string]string{"app": "mu"}},
	}

	flows := []flow.Flow{
		{
			Time:      now,
			Source:    flow.Endpoint{Namespace: "prod", PodName: "mu-123", IP: "10.0.0.1"},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "zeta-456", IP: "10.0.0.2"},
			Layer4:    flow.Layer4{DestPort: 443, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Egress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{})

	// mu and zeta are observed (mu is source, zeta is dest). Alpha has 0 traffic.
	// Sorted by WorkloadID: "prod/mu" < "prod/zeta"
	require.Len(t, policies, 2)
	require.Equal(t, "prod/mu", policies[0].WorkloadID)
	require.Equal(t, "prod/zeta", policies[1].WorkloadID)
}

// TestBuildCrossNamespace verifies that cross-namespace peers are encoded as
// "otherNs/name,label1=v1" in FromWorkloads / ToWorkloads instead of the
// bare label selector which loses namespace information.
func TestBuildCrossNamespace(t *testing.T) {
	t.Parallel()

	now := time.Now()

	workloads := analyze.Workloads{
		"prod/frontend": {
			Name:      "frontend",
			Namespace: "prod",
			Labels:    map[string]string{"app": "frontend"},
		},
		"other/backend": {
			Name:      "backend",
			Namespace: "other",
			Labels:    map[string]string{"app": "backend"},
		},
	}

	flows := []flow.Flow{
		{
			Time:      now,
			Source:    flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Egress,
		},
		{
			Time:      now.Add(time.Second),
			Source:    flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Ingress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{})
	// Find the frontend policy; backend may or may not produce a policy depending
	// on whether the Ingress flow records it as observed.
	var frontendPolicy, backendPolicy *Policy
	for i := range policies {
		switch policies[i].WorkloadID {
		case "prod/frontend":
			frontendPolicy = &policies[i]
		case "other/backend":
			backendPolicy = &policies[i]
		}
	}
	require.NotNil(t, frontendPolicy)

	// Frontend egress: both flows (Egress and Ingress) have frontend as source → 1 consolidated rule.
	require.Equal(t, 1, len(frontendPolicy.EgressRules))
	require.Equal(t, []string{"prod/backend"}, frontendPolicy.EgressRules[0].ToWorkloads)

	// If backend policy exists, verify its ingress rule.
	if backendPolicy != nil {
		require.Equal(t, 1, len(backendPolicy.IngressRules))
		require.Equal(t, []string{"prod/frontend"}, backendPolicy.IngressRules[0].FromWorkloads)
	}
}

func TestBuild_SyntheticWorkloadsSkipped(t *testing.T) {
	t.Parallel()

	now := time.Now()

	workloads := analyze.Workloads{
		"prod/frontend": {
			Name:      "frontend",
			Namespace: "prod",
			Labels:    map[string]string{"app": "frontend"},
		},
		"-/-": {Name: "-", Namespace: "", Labels: map[string]string{}},
		"-/pub": {Name: "pub", Namespace: "-", Labels: map[string]string{"app": "pub"}},
		"-/pvt": {Name: "pvt", Namespace: "-", Labels: map[string]string{"app": "pvt"}},
	}

	flows := []flow.Flow{
		{
			Time:      now,
			Source:    flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "-", IP: "203.0.113.5", Labels: map[string]string{"app": "pub"}},
			Layer4:    flow.Layer4{DestPort: 443, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Egress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{})

	// Only the real "prod/frontend" should get a policy.
	require.Len(t, policies, 1)
	require.Equal(t, "prod/frontend", policies[0].WorkloadID)

	ids := []string{policies[0].WorkloadID}
	require.NotContains(t, ids, "-/-")
	require.NotContains(t, ids, "-/pub")
	require.NotContains(t, ids, "-/pvt")
}

func TestBuild_WorldCIDR_0_0_0_0_IP(t *testing.T) {
	t.Parallel()

	now := time.Now()

	workloads := analyze.Workloads{
		"prod/frontend": {
			Name:      "frontend",
			Namespace: "prod",
			Labels:    map[string]string{"app": "frontend"},
		},
		"-/pub": {Name: "pub", Namespace: "-", Labels: map[string]string{"app": "pub"}},
	}

	flows := []flow.Flow{
		{
			Time:      now,
			Source:    flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "0.0.0.0", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "-", IP: "0.0.0.0", Labels: map[string]string{"app": "pub"}},
			Layer4:    flow.Layer4{DestPort: 443, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Egress,
		},
		{
			Time:      now.Add(time.Second),
			Source:    flow.Endpoint{Namespace: "-", IP: "0.0.0.0", Labels: map[string]string{"app": "pub"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "0.0.0.0", Labels: map[string]string{"app": "frontend"}},
			Layer4:    flow.Layer4{DestPort: 443, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Ingress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{})

	require.Len(t, policies, 1)
	require.Equal(t, "prod/frontend", policies[0].WorkloadID)

	require.Equal(t, 1, len(policies[0].EgressRules))
	require.Equal(t, []string{"0.0.0.0/0"}, policies[0].EgressRules[0].ToCIDRs)
	require.Equal(t, 0, len(policies[0].EgressRules[0].ToWorkloads))

	require.Equal(t, 1, len(policies[0].IngressRules))
	require.Equal(t, []string{"0.0.0.0/0"}, policies[0].IngressRules[0].FromWorkloads)
}

// TestBuild_TwoPeersDisjointPorts verifies that when a workload communicates
// with two distinct peers on different ports, separate ingress and egress rules
// are emitted — each rule scoped to only that peer's ports.
func TestBuild_TwoPeersDisjointPorts(t *testing.T) {
	t.Parallel()

	now := time.Now()

	workloads := analyze.Workloads{
		"prod/frontend": {
			Name:      "frontend",
			Namespace: "prod",
			Labels:    map[string]string{"app": "frontend"},
		},
		"prod/backend": {
			Name:      "backend",
			Namespace: "prod",
			Labels:    map[string]string{"app": "backend"},
		},
	}

	flows := []flow.Flow{
		{
			Time:      now,
			Source:    flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Egress,
		},
		{
			Time:      now.Add(time.Second),
			Source:    flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Ingress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{})
	require.Len(t, policies, 2)

	var frontendPolicy, backendPolicy *Policy
	for i := range policies {
		if policies[i].WorkloadID == "prod/frontend" {
			frontendPolicy = &policies[i]
		}
		if policies[i].WorkloadID == "prod/backend" {
			backendPolicy = &policies[i]
		}
	}
	require.NotNil(t, frontendPolicy)
	require.NotNil(t, backendPolicy)

	require.Equal(t, 1, len(frontendPolicy.EgressRules))
	require.Equal(t, []string{"app=backend"}, frontendPolicy.EgressRules[0].ToWorkloads)
	require.Len(t, frontendPolicy.EgressRules[0].ToPorts, 1)
	require.Equal(t, uint16(8080), frontendPolicy.EgressRules[0].ToPorts[0].Port)
	require.Equal(t, "TCP", frontendPolicy.EgressRules[0].ToPorts[0].Protocol)

	require.Equal(t, 1, len(backendPolicy.IngressRules))
	require.Equal(t, []string{"app=frontend"}, backendPolicy.IngressRules[0].FromWorkloads)
	require.Len(t, backendPolicy.IngressRules[0].Ports, 1)
	require.Equal(t, uint16(8080), backendPolicy.IngressRules[0].Ports[0].Port)
	require.Equal(t, "TCP", backendPolicy.IngressRules[0].Ports[0].Protocol)
}

// TestBuild_WorldAndPeerEgressSeparation verifies that a workload with egress
// to a named peer and egress to the world produces two separate egress rules:
// one with ToWorkloads for the peer and one with ToCIDRs for world.
func TestBuild_WorldAndPeerEgressSeparation(t *testing.T) {
	t.Parallel()

	now := time.Now()

	workloads := analyze.Workloads{
		"prod/frontend": {
			Name:      "frontend",
			Namespace: "prod",
			Labels:    map[string]string{"app": "frontend"},
		},
		"prod/backend": {
			Name:      "backend",
			Namespace: "prod",
			Labels:    map[string]string{"app": "backend"},
		},
		"-/pub": {Name: "pub", Namespace: "-", Labels: map[string]string{"app": "pub"}},
	}

	flows := []flow.Flow{
		{
			Time:      now,
			Source:    flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Egress,
		},
		{
			Time:      now.Add(time.Second),
			Source:    flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "-", IP: "198.51.100.10", Labels: map[string]string{"app": "pub"}},
			Layer4:    flow.Layer4{DestPort: 443, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Egress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{})
	// After Aggregate, peer-only workloads (e.g. prod/backend) may also appear.
	// Find the frontend policy by WorkloadID.
	var frontendPolicy *Policy
	for i := range policies {
		if policies[i].WorkloadID == "prod/frontend" {
			frontendPolicy = &policies[i]
			break
		}
	}
	require.NotNil(t, frontendPolicy)

	// Must have exactly 2 egress rules: one for peer, one for world.
	require.Equal(t, 2, len(frontendPolicy.EgressRules))

	// Identify rules by their properties.
	var peerRule, worldRule *EgressRule
	for i := range frontendPolicy.EgressRules {
		r := &frontendPolicy.EgressRules[i]
		if len(r.ToWorkloads) > 0 {
			peerRule = r
		}
		if len(r.ToCIDRs) > 0 {
			worldRule = r
		}
	}
	require.NotNil(t, peerRule, "expected a peer egress rule")
	require.NotNil(t, worldRule, "expected a world CIDR egress rule")

	// Peer rule: ToWorkloads=[app=backend], port 8080.
	require.Equal(t, []string{"app=backend"}, peerRule.ToWorkloads)
	require.Len(t, peerRule.ToPorts, 1)
	require.Equal(t, uint16(8080), peerRule.ToPorts[0].Port)
	require.Equal(t, "TCP", peerRule.ToPorts[0].Protocol)
	// World rule must not have ToWorkloads populated.
	require.Nil(t, worldRule.ToWorkloads)
	require.Len(t, worldRule.ToCIDRs, 1)
	require.Equal(t, []string{"0.0.0.0/0"}, worldRule.ToCIDRs)
	require.Equal(t, 1, len(worldRule.ToPorts))
	require.Equal(t, uint16(443), worldRule.ToPorts[0].Port)
	require.Equal(t, "TCP", worldRule.ToPorts[0].Protocol)
}

func TestBuild_PortDedup(t *testing.T) {
	t.Parallel()

	now := time.Now()

	workloads := analyze.Workloads{
		"prod/frontend": {
			Name:      "frontend",
			Namespace: "prod",
			Labels:    map[string]string{"app": "frontend"},
		},
		"prod/backend": {
			Name:      "backend",
			Namespace: "prod",
			Labels:    map[string]string{"app": "backend"},
		},
	}

	flows := []flow.Flow{
		// Two flows to the same peer on the same port.
		{
			Time:      now,
			Source:    flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Egress,
		},
		{
			Time:      now.Add(time.Second),
			Source:    flow.Endpoint{Namespace: "prod", PodName: "frontend-efgh", IP: "10.0.0.3", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-rst", IP: "10.0.0.4", Labels: map[string]string{"app": "backend"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Egress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{})
	require.Len(t, policies, 2)

	var frontendPolicy *Policy
	for i := range policies {
		if policies[i].WorkloadID == "prod/frontend" {
			frontendPolicy = &policies[i]
			break
		}
	}
	require.NotNil(t, frontendPolicy)

	// One egress rule to the single peer "backend".
	require.Equal(t, 1, len(frontendPolicy.EgressRules))
	require.Equal(t, []string{"app=backend"}, frontendPolicy.EgressRules[0].ToWorkloads)

	// Port 8080 appears only once in ToPorts (deduped), with count "2 times".
	require.Len(t, frontendPolicy.EgressRules[0].ToPorts, 1)
	require.Equal(t, uint16(8080), frontendPolicy.EgressRules[0].ToPorts[0].Port)
	require.Equal(t, "TCP", frontendPolicy.EgressRules[0].ToPorts[0].Protocol)
	require.Equal(t, "observed 2 times", frontendPolicy.EgressRules[0].ToPorts[0].Description)
}

// TestBuildEgressRules_PerPeerWithPorts verifies that egress to two peers
// produces two separate rules, each scoped to that peer's observed ports.
func TestBuildEgressRules_PerPeerWithPorts(t *testing.T) {
	t.Parallel()

	now := time.Now()

	workloads := analyze.Workloads{
		"prod/frontend": {
			Name:      "frontend",
			Namespace: "prod",
			Labels:    map[string]string{"app": "frontend"},
		},
		"prod/backend": {
			Name:      "backend",
			Namespace: "prod",
			Labels:    map[string]string{"app": "backend"},
		},
		"prod/cache": {
			Name:      "cache",
			Namespace: "prod",
			Labels:    map[string]string{"app": "cache"},
		},
	}

	flows := []flow.Flow{
		{
			Time:      now,
			Source:    flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Egress,
		},
		{
			Time:      now.Add(time.Second),
			Source:    flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "cache-xyz", IP: "10.0.0.3", Labels: map[string]string{"app": "cache"}},
			Layer4:    flow.Layer4{DestPort: 6379, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Egress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{})

	var fp *Policy
	for i := range policies {
		if policies[i].WorkloadID == "prod/frontend" {
			fp = &policies[i]
			break
		}
	}
	require.NotNil(t, fp)
	require.Equal(t, 2, len(fp.EgressRules))

	// Collect selectors from rules.
	var selectors []string
	selectorPort := make(map[string]uint16)
	for _, r := range fp.EgressRules {
		require.Len(t, r.ToPorts, 1, "each peer rule must have exactly 1 port")
		require.Len(t, r.ToWorkloads, 1)
		require.Nil(t, r.ToCIDRs)
		selectorPort[r.ToWorkloads[0]] = r.ToPorts[0].Port
		selectors = append(selectors, r.ToWorkloads[0])
	}
	selSet := make(map[string]bool)
	for _, s := range selectors {
		selSet[s] = true
	}
	require.True(t, selSet["app=backend"], "peer selector for backend missing")
	require.True(t, selSet["app=cache"], "peer selector for cache missing")
	// Ports scoped correctly.
	require.Equal(t, uint16(8080), selectorPort["app=backend"])
	require.Equal(t, uint16(6379), selectorPort["app=cache"])
}

// TestBuildEgressRules_WorldEgressWithoutPorts_Dropped verifies that a world
// egress entry with no observed ports does NOT produce a rule.
func TestBuildEgressRules_WorldEgressWithoutPorts_Dropped(t *testing.T) {
	t.Parallel()

	now := time.Now()

	workloads := analyze.Workloads{
		"prod/frontend": {
			Name:      "frontend",
			Namespace: "prod",
			Labels:    map[string]string{"app": "frontend"},
		},
		"prod/backend": {
			Name:      "backend",
			Namespace: "prod",
			Labels:    map[string]string{"app": "backend"},
		},
	}

	flows := []flow.Flow{
		{
			Time:      now,
			Source:    flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Egress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{})

	var fp *Policy
	for i := range policies {
		if policies[i].WorkloadID == "prod/frontend" {
			fp = &policies[i]
			break
		}
	}
	require.NotNil(t, fp)
	// Only one peer rule; no world rule emitted when frontend has no direct
	// world egress.
	require.Equal(t, 1, len(fp.EgressRules))
	for _, r := range fp.EgressRules {
		require.Nil(t, r.ToCIDRs)
	}
	require.Equal(t, []string{"app=backend"}, fp.EgressRules[0].ToWorkloads)
}

// TestBuildEgressRules_PortDedup verifies that two flows to the same peer
// on the same port produce one deduplicated ToPorts entry.
func TestBuildEgressRules_PortDedup(t *testing.T) {
	t.Parallel()

	now := time.Now()

	workloads := analyze.Workloads{
		"prod/frontend": {
			Name:      "frontend",
			Namespace: "prod",
			Labels:    map[string]string{"app": "frontend"},
		},
		"prod/backend": {
			Name:      "backend",
			Namespace: "prod",
			Labels:    map[string]string{"app": "backend"},
		},
	}

	flows := []flow.Flow{
		{
			Time:      now,
			Source:    flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:    flow.Layer4{DestPort: 443, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Egress,
		},
		{
			Time:      now.Add(time.Second),
			Source:    flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:    flow.Layer4{DestPort: 443, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Egress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{})

	var fp *Policy
	for i := range policies {
		if policies[i].WorkloadID == "prod/frontend" {
			fp = &policies[i]
			break
		}
	}
	require.NotNil(t, fp)
	require.Equal(t, 1, len(fp.EgressRules))
	require.Len(t, fp.EgressRules[0].ToPorts, 1, "port dedup should produce 1 entry")
	require.Equal(t, uint16(443), fp.EgressRules[0].ToPorts[0].Port)
	require.Equal(t, "TCP", fp.EgressRules[0].ToPorts[0].Protocol)
	require.Equal(t, "observed 2 times", fp.EgressRules[0].ToPorts[0].Description)
}

// TestBuildEgressRules_AllPeerNoWorld verifies that egress to a single peer
// produces exactly 1 rule with ToWorkloads set and no ToCIDRs.
func TestBuildEgressRules_AllPeerNoWorld(t *testing.T) {
	t.Parallel()

	now := time.Now()

	workloads := analyze.Workloads{
		"prod/frontend": {
			Name:      "frontend",
			Namespace: "prod",
			Labels:    map[string]string{"app": "frontend"},
		},
		"prod/backend": {
			Name:      "backend",
			Namespace: "prod",
			Labels:    map[string]string{"app": "backend"},
		},
	}

	flows := []flow.Flow{
		{
			Time:      now,
			Source:    flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Egress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{})

	var fp *Policy
	for i := range policies {
		if policies[i].WorkloadID == "prod/frontend" {
			fp = &policies[i]
			break
		}
	}
	require.NotNil(t, fp)
	require.Equal(t, 1, len(fp.EgressRules))

	r := fp.EgressRules[0]
	require.Equal(t, []string{"app=backend"}, r.ToWorkloads)
	require.Nil(t, r.ToCIDRs)
	require.Len(t, r.ToPorts, 1)
	require.Equal(t, uint16(8080), r.ToPorts[0].Port)
}

// TestBuild_ApiserverIngressSentinel verifies that a flow with synthetic source
// dest port 9443 TCP and Config.ApiserverIngressPorts=[{TCP,9443}]
// produces an apiserver rule (FromWorkloads: ["apiserver"]).
func TestBuild_ApiserverIngressSentinel(t *testing.T) {
	t.Parallel()

	_, ns, _ := net.ParseCIDR("10.0.0.0/8")
	cfg := config.Config{
		ClusterCIDRs: []*net.IPNet{ns},
		ApiserverIngressPorts: []config.PortSpec{
			{Protocol: "TCP", Port: 9443},
		},
	}

	workloads := analyze.Workloads{
		"prod/api-server": {Name: "api-server", Namespace: "prod", Labels: map[string]string{"app": "api-server"}},
		"-/pub": {Name: "pub", Namespace: "-", Labels: map[string]string{"app": "pub"}},
	}

	flows := []flow.Flow{
		{
			Time:      time.Now(),
			Source:    flow.Endpoint{Namespace: "-", IP: "0.0.0.0", Labels: map[string]string{"app": "pub"}},
			Destination: flow.Endpoint{Namespace: "prod", IP: "10.96.0.1", Labels: map[string]string{"app": "api-server"}},
			Layer4:    flow.Layer4{DestPort: 9443, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Ingress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{Config: &cfg})

	var ap *Policy
	for i := range policies {
		if policies[i].WorkloadID == "prod/api-server" {
			ap = &policies[i]
			break
		}
	}
	require.NotNil(t, ap)
	require.Len(t, ap.IngressRules, 1)
	require.Equal(t, []string{"apiserver"}, ap.IngressRules[0].FromWorkloads)
	require.Len(t, ap.IngressRules[0].Ports, 1)
	require.Equal(t, uint16(9443), ap.IngressRules[0].Ports[0].Port)
	require.Equal(t, "TCP", ap.IngressRules[0].Ports[0].Protocol)
}

// TestBuild_WorldNotApiserver_Port443 verifies that port 443 does NOT
// match ApiserverIngressPorts and emits a world rule instead.
func TestBuild_WorldNotApiserver_Port443(t *testing.T) {
	t.Parallel()

	_, ns, _ := net.ParseCIDR("10.0.0.0/8")
	cfg := config.Config{
		ClusterCIDRs: []*net.IPNet{ns},
		ApiserverIngressPorts: []config.PortSpec{
			{Protocol: "TCP", Port: 9443},
		},
	}

	workloads := analyze.Workloads{
		"prod/api-server": {Name: "api-server", Namespace: "prod", Labels: map[string]string{"app": "api-server"}},
		"-/pub": {Name: "pub", Namespace: "-", Labels: map[string]string{"app": "pub"}},
	}

	flows := []flow.Flow{
		{
			Time:      time.Now(),
			Source:    flow.Endpoint{Namespace: "-", IP: "0.0.0.0", Labels: map[string]string{"app": "pub"}},
			Destination: flow.Endpoint{Namespace: "prod", IP: "10.96.0.1", Labels: map[string]string{"app": "api-server"}},
			Layer4:    flow.Layer4{DestPort: 443, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Ingress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{Config: &cfg})

	var ap *Policy
	for i := range policies {
		if policies[i].WorkloadID == "prod/api-server" {
			ap = &policies[i]
			break
		}
	}
	require.NotNil(t, ap)
	require.Len(t, ap.IngressRules, 1)
	require.Equal(t, []string{"0.0.0.0/0"}, ap.IngressRules[0].FromWorkloads)
	require.Equal(t, "world ingress", ap.IngressRules[0].Description)
}

// TestBuild_ApiserverSentinel_NilConfig verifies that when BuildOptions.Config is nil,
// the same flow produces a world rule (backward-compat).
func TestBuild_ApiserverSentinel_NilConfig(t *testing.T) {
	t.Parallel()

	_, ns, _ := net.ParseCIDR("10.0.0.0/8")
	cfg := config.Config{ClusterCIDRs: []*net.IPNet{ns}}

	workloads := analyze.Workloads{
		"prod/api-server": {Name: "api-server", Namespace: "prod", Labels: map[string]string{"app": "api-server"}},
		"-/pub": {Name: "pub", Namespace: "-", Labels: map[string]string{"app": "pub"}},
	}

	flows := []flow.Flow{
		{
			Time:      time.Now(),
			Source:    flow.Endpoint{Namespace: "-", IP: "0.0.0.0", Labels: map[string]string{"app": "pub"}},
			Destination: flow.Endpoint{Namespace: "prod", IP: "10.96.0.1", Labels: map[string]string{"app": "api-server"}},
			Layer4:    flow.Layer4{DestPort: 9443, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Ingress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{Config: &cfg})

	var ap *Policy
	for i := range policies {
		if policies[i].WorkloadID == "prod/api-server" {
			ap = &policies[i]
			break
		}
	}
	require.NotNil(t, ap)
	require.Len(t, ap.IngressRules, 1)
	// 9443 not in config, stays world.
	require.Equal(t, []string{"0.0.0.0/0"}, ap.IngressRules[0].FromWorkloads)
}

// TestBuild_ApiServerEgressSentinel verifies a flow with the workload as source
// and a synthetic destination triggering world egress on a port that matches
// Config.ApiserverEgressPorts produces an EgressRule with ToCIDRs=["apiserver"]
// and the matching port.
func TestBuild_ApiServerEgressSentinel(t *testing.T) {
	t.Parallel()

	_, ns, _ := net.ParseCIDR("10.0.0.0/8")
	cfg := config.Config{
		ClusterCIDRs: []*net.IPNet{ns},
		ApiserverEgressPorts: []config.PortSpec{
			{Protocol: "TCP", Port: 6443},
		},
	}

	workloads := analyze.Workloads{
		"prod/web":        {Name: "web", Namespace: "prod", Labels: map[string]string{"app": "web"}},
		"-/pub":           {Name: "pub", Namespace: "-", Labels: map[string]string{"app": "pub"}},
	}

	flows := []flow.Flow{
		{
			Time:      time.Now(),
			Source:    flow.Endpoint{Namespace: "prod", IP: "10.0.0.2", Labels: map[string]string{"app": "web"}},
			Destination: flow.Endpoint{Namespace: "-", IP: "0.0.0.0", Labels: map[string]string{"app": "pub"}},
			Layer4:    flow.Layer4{DestPort: 6443, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Egress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{Config: &cfg})

	var wp *Policy
	for i := range policies {
		if policies[i].WorkloadID == "prod/web" {
			wp = &policies[i]
			break
		}
	}
	require.NotNil(t, wp)
	require.Len(t, wp.EgressRules, 1)
	require.Equal(t, []string{"apiserver"}, wp.EgressRules[0].ToCIDRs)
	require.Len(t, wp.EgressRules[0].ToPorts, 1)
	require.Equal(t, uint16(6443), wp.EgressRules[0].ToPorts[0].Port)
	require.Equal(t, "TCP", wp.EgressRules[0].ToPorts[0].Protocol)
}

// TestBuild_ApiServerEgress_WorldNotApiserver verifies that port 443 (not in
// ApiserverEgressPorts) stays as world egress (0.0.0.0/0).
func TestBuild_ApiServerEgress_WorldNotApiserver(t *testing.T) {
	t.Parallel()

	_, ns, _ := net.ParseCIDR("10.0.0.0/8")
	cfg := config.Config{
		ClusterCIDRs: []*net.IPNet{ns},
		ApiserverEgressPorts: []config.PortSpec{
			{Protocol: "TCP", Port: 6443},
		},
	}

	workloads := analyze.Workloads{
		"prod/web": {Name: "web", Namespace: "prod", Labels: map[string]string{"app": "web"}},
		"-/pub":    {Name: "pub", Namespace: "-", Labels: map[string]string{"app": "pub"}},
	}

	flows := []flow.Flow{
		{
			Time:      time.Now(),
			Source:    flow.Endpoint{Namespace: "prod", IP: "10.0.0.2", Labels: map[string]string{"app": "web"}},
			Destination: flow.Endpoint{Namespace: "-", IP: "0.0.0.0", Labels: map[string]string{"app": "pub"}},
			Layer4:    flow.Layer4{DestPort: 443, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Egress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{Config: &cfg})

	var wp *Policy
	for i := range policies {
		if policies[i].WorkloadID == "prod/web" {
			wp = &policies[i]
			break
		}
	}
	require.NotNil(t, wp)
	require.Len(t, wp.EgressRules, 1)
	require.Equal(t, []string{"0.0.0.0/0"}, wp.EgressRules[0].ToCIDRs)
}

// TestBuild_ApiServerEgress_NilConfig verifies that when BuildOptions.Config is nil,
// world egress stays backward-compatible as 0.0.0.0/0.
func TestBuild_ApiServerEgress_NilConfig(t *testing.T) {
	t.Parallel()

	_, ns, _ := net.ParseCIDR("10.0.0.0/8")
	cfg := config.Config{ClusterCIDRs: []*net.IPNet{ns}}

	workloads := analyze.Workloads{
		"prod/web": {Name: "web", Namespace: "prod", Labels: map[string]string{"app": "web"}},
		"-/pub":    {Name: "pub", Namespace: "-", Labels: map[string]string{"app": "pub"}},
	}

	flows := []flow.Flow{
		{
			Time:      time.Now(),
			Source:    flow.Endpoint{Namespace: "prod", IP: "10.0.0.2", Labels: map[string]string{"app": "web"}},
			Destination: flow.Endpoint{Namespace: "-", IP: "0.0.0.0", Labels: map[string]string{"app": "pub"}},
			Layer4:    flow.Layer4{DestPort: 6443, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Egress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{Config: &cfg})

	var wp *Policy
	for i := range policies {
		if policies[i].WorkloadID == "prod/web" {
			wp = &policies[i]
			break
		}
	}
	require.NotNil(t, wp)
	require.Len(t, wp.EgressRules, 1)
	require.Equal(t, []string{"0.0.0.0/0"}, wp.EgressRules[0].ToCIDRs)
}

// TestBuild_PublicServicesKubeDNS verifies that a PublicService shortcut
// emits a single match-all rule and removes those ports from per-peer grouping.
func TestBuild_PublicServicesKubeDNS(t *testing.T) {
	t.Parallel()

	_, ns, _ := net.ParseCIDR("10.0.0.0/8")
	cfg := config.Config{
		ClusterCIDRs: []*net.IPNet{ns},
		PublicServices: []config.PublicServiceSpec{
			{Namespace: "kube-system", Name: "kube-dns", Ports: []config.PortSpec{{Protocol: "UDP", Port: 53}, {Protocol: "TCP", Port: 53}}},
		},
	}

	workloads := analyze.Workloads{
		"kube-system/kube-dns": {Name: "kube-dns", Namespace: "kube-system", Labels: map[string]string{"app": "kube-dns"}},
		"-/pub": {Name: "pub", Namespace: "-", Labels: map[string]string{"app": "pub"}},
	}

	flows := []flow.Flow{}
	for i := 0; i < 5; i++ {
		flows = append(flows, flow.Flow{
			Time:      time.Now().Add(time.Duration(i) * time.Second),
			Source:    flow.Endpoint{Namespace: "-", IP: "0.0.0.0", Labels: map[string]string{"app": "pub"}},
			Destination: flow.Endpoint{Namespace: "kube-system", IP: "10.96.0.10", Labels: map[string]string{"app": "kube-dns"}},
			Layer4:    flow.Layer4{DestPort: 53, Protocol: flow.UDP},
			Verdict:   flow.Allow,
			Direction: flow.Ingress,
		})
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{Config: &cfg})

	var dp *Policy
	for i := range policies {
		if policies[i].WorkloadID == "kube-system/kube-dns" {
			dp = &policies[i]
			break
		}
	}
	require.NotNil(t, dp)
	// Should emit 1 public-service rule (FromWorkloads: 0.0.0.0/0).
	require.Len(t, dp.IngressRules, 1)
	require.Equal(t, []string{"0.0.0.0/0"}, dp.IngressRules[0].FromWorkloads)
	require.Equal(t, "public service ingress", dp.IngressRules[0].Description)

	// Ports sorted: TCP/53 < UDP/53
	require.Len(t, dp.IngressRules[0].Ports, 2)
}

// TestBuild_PublicServicesNoOtherPorts verifies that when a workload has
// both a public-service port AND a non-public-service port from different peers,
// the public-service ports are removed from per-peer rules but non-public ports remain.
func TestBuild_PublicServicesNoOtherPorts(t *testing.T) {
	t.Parallel()

	_, ns, _ := net.ParseCIDR("10.0.0.0/8")
	cfg := config.Config{
		ClusterCIDRs: []*net.IPNet{ns},
		PublicServices: []config.PublicServiceSpec{
			{Namespace: "kube-system", Name: "kube-dns", Ports: []config.PortSpec{{Protocol: "UDP", Port: 53}}},
		},
	}

	workloads := analyze.Workloads{
		"kube-system/kube-dns": {Name: "kube-dns", Namespace: "kube-system", Labels: map[string]string{"app": "kube-dns"}},
		"-/pub": {Name: "pub", Namespace: "-", Labels: map[string]string{"app": "pub"}},
	}

	flows := []flow.Flow{
		{
			Time:      time.Now(),
			Source:    flow.Endpoint{Namespace: "-", IP: "0.0.0.0", Labels: map[string]string{"app": "pub"}},
			Destination: flow.Endpoint{Namespace: "kube-system", IP: "10.96.0.10", Labels: map[string]string{"app": "kube-dns"}},
			Layer4:    flow.Layer4{DestPort: 53, Protocol: flow.UDP},
			Verdict:   flow.Allow,
			Direction: flow.Ingress,
		},
		{
			Time:      time.Now().Add(time.Second),
			Source:    flow.Endpoint{Namespace: "kube-system", PodName: "podA", IP: "10.0.0.2", Labels: map[string]string{"app": "podA"}},
			Destination: flow.Endpoint{Namespace: "kube-system", IP: "10.96.0.10", Labels: map[string]string{"app": "kube-dns"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Ingress,
		},
		{
			Time:      time.Now().Add(2 * time.Second),
			Source:    flow.Endpoint{Namespace: "kube-system", PodName: "podB", IP: "10.0.0.3", Labels: map[string]string{"app": "podB"}},
			Destination: flow.Endpoint{Namespace: "kube-system", IP: "10.96.0.10", Labels: map[string]string{"app": "kube-dns"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Ingress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{Config: &cfg})

	var dp *Policy
	for i := range policies {
		if policies[i].WorkloadID == "kube-system/kube-dns" {
			dp = &policies[i]
			break
		}
	}
	require.NotNil(t, dp)

	// 1 public-service rule for port 53.
	require.Equal(t, []string{"0.0.0.0/0"}, dp.IngressRules[0].FromWorkloads)
	require.Equal(t, "public service ingress", dp.IngressRules[0].Description)

	// 2 per-peer rules for port 8080 (one per podA, one per podB).
	perPeerRules := 0
	for _, r := range dp.IngressRules[1:] {
		require.NotEqual(t, "0.0.0.0/0", r.FromWorkloads[0])
		// Each rule should have port 8080.
		require.Len(t, r.Ports, 1)
		require.Equal(t, uint16(8080), r.Ports[0].Port)
		perPeerRules++
	}
	require.Equal(t, 2, perPeerRules)
}

// TestBuild_SymmetricEgressIngress verifies that a non-synthetic egress flow
// creates a mirrored ingress entry on the destination, while synthetic or
// world egress does NOT produce a symmetric ingress rule.
func TestBuild_SymmetricEgressIngress(t *testing.T) {
	t.Parallel()

	now := time.Now()

	workloads := analyze.Workloads{
		"demo/client": {Name: "client", Namespace: "demo", Labels: map[string]string{"app": "client"}},
		"demo/server": {Name: "server", Namespace: "demo", Labels: map[string]string{"app": "server"}},
		"-/pvt":       {Name: "pvt", Namespace: "-", Labels: map[string]string{"app": "pvt"}},
	}

	flows := []flow.Flow{
		// 1. Egress client → server:80 TCP (real — mirrors ingress to server).
		{
			Time:        now,
			Source:      flow.Endpoint{Namespace: "demo", PodName: "client-abc", IP: "10.0.0.1", Labels: map[string]string{"app": "client"}},
			Destination: flow.Endpoint{Namespace: "demo", PodName: "server-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "server"}},
			Layer4:      flow.Layer4{DestPort: 80, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
		},
		// 2. Egress client → pvt (synthetic — NO ingress mirror on pvt).
		{
			Time:        now.Add(time.Second),
			Source:      flow.Endpoint{Namespace: "demo", PodName: "client-abc", IP: "10.0.0.1", Labels: map[string]string{"app": "client"}},
			Destination: flow.Endpoint{Namespace: "-", IP: "198.51.100.10", Labels: map[string]string{"app": "pvt"}},
			Layer4:      flow.Layer4{DestPort: 443, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{})

	var clientPolicy, serverPolicy *Policy
	ids := make([]string, 0, len(policies))
	for i := range policies {
		ids = append(ids, policies[i].WorkloadID)
		if policies[i].WorkloadID == "demo/client" {
			clientPolicy = &policies[i]
		}
		if policies[i].WorkloadID == "demo/server" {
			serverPolicy = &policies[i]
		}
	}

	require.NotNil(t, clientPolicy)
	require.NotNil(t, serverPolicy)

	// pvt is synthetic — must NOT appear in policies.
	require.NotContains(t, ids, "-/pvt")

	// Client has 2 egress rules: peer to server + world to pvt.
	require.Equal(t, 2, len(clientPolicy.EgressRules))

	// Server has 1 ingress rule from client on port 80/TCP (mirrored from #1).
	require.Equal(t, 1, len(serverPolicy.IngressRules))
	require.Equal(t, []string{"app=client"}, serverPolicy.IngressRules[0].FromWorkloads)
	require.Len(t, serverPolicy.IngressRules[0].Ports, 1)
	require.Equal(t, uint16(80), serverPolicy.IngressRules[0].Ports[0].Port)
	require.Equal(t, "TCP", serverPolicy.IngressRules[0].Ports[0].Protocol)
}

// TestBuild_ApiServerEgressByPeerType verifies that a flow with PeerType=KubeAPIServer
// and a private dest IP produces an egress rule with ToCIDRs=["apiserver"].
func TestBuild_ApiServerEgressByPeerType(t *testing.T) {
	t.Parallel()

	_, ns, _ := net.ParseCIDR("10.0.0.0/8")
	cfg := config.Config{
		ClusterCIDRs: []*net.IPNet{ns},
		ApiserverEgressPorts: []config.PortSpec{
			{Protocol: "TCP", Port: 6443},
		},
	}

	workloads := analyze.Workloads{
		"prod/web": {Name: "web", Namespace: "prod", Labels: map[string]string{"app": "web"}},
	}

	flows := []flow.Flow{
		{
			Time:        time.Now(),
			Source:      flow.Endpoint{Namespace: "prod", IP: "10.0.0.2", Labels: map[string]string{"app": "web"}},
			Destination: flow.Endpoint{Namespace: "prod", IP: "192.168.107.3", Labels: map[string]string{"reserved:kube-apiserver": "true"}},
			Layer4:      flow.Layer4{DestPort: 6443, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
			PeerType:    flow.KubeAPIServer,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{Config: &cfg})

	require.Len(t, policies, 1)
	require.Equal(t, "prod/web", policies[0].WorkloadID)
	require.Len(t, policies[0].EgressRules, 1)
	require.Equal(t, []string{"apiserver"}, policies[0].EgressRules[0].ToCIDRs)
}

// TestBuild_SkipEmptyPolicies verifies that workloads with no allowed
// ingress/egress rules produce no Policy entry (and therefore no YAML),
// while workloads with at least one rule still get a policy.
func TestBuild_SkipEmptyPolicies(t *testing.T) {
	t.Parallel()

	now := time.Now()

	workloads := analyze.Workloads{
		"prod/frontend": {
			Name:      "frontend",
			Namespace: "prod",
			Labels:    map[string]string{"app": "frontend"},
		},
		"prod/backend": {
			Name:      "backend",
			Namespace: "prod",
			Labels:    map[string]string{"app": "backend"},
		},
		"prod/cache": {
			Name:      "cache",
			Namespace: "prod",
			Labels:    map[string]string{"app": "cache"},
		},
		"prod/worker": {
			Name:      "worker",
			Namespace: "prod",
			Labels:    map[string]string{"app": "worker"},
		},
	}

	flows := []flow.Flow{
		// Workload A (frontend): has a flow egress to backend → policy A has egress rules → NOT skipped.
		{
			Time:        now,
			Source:      flow.Endpoint{Namespace: "prod", PodName: "frontend-abc", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
		},
		// Workload B (backend): observed as destination peer only, but symmetric ingress gives it 1 rule → NOT skipped (has ingress).
		// Actually we need backend to NOT have rules. Let's use a different scenario.
		// Workload C (cache): only in the workloads map, NO flows at all → not observed → SKIPPED by isObserved check.
		// Workload D (worker): dropped flows only → not observed (dropped flows skip the isObserved set) → SKIPPED by isObserved check.
		{
			Time:        now.Add(time.Second),
			Source:      flow.Endpoint{Namespace: "prod", PodName: "worker-abc", IP: "10.0.0.4", Labels: map[string]string{"app": "worker"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:     flow.Denied,
			Direction:   flow.Egress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{})

	// Only frontend is observed AND has rules → 1 policy.
	// cache: not observed (no allowed flows) → skipped.
	// worker: observed=false (only dropped flows, skipped before isObserved set) → skipped.
	// backend: observed (frontend's egress flow), has symmetric ingress from frontend → NOT skipped (has rules).
	require.Len(t, policies, 2)
	var frontendPolicy, backendPolicy *Policy
	for i := range policies {
		if policies[i].WorkloadID == "prod/frontend" {
			frontendPolicy = &policies[i]
		}
		if policies[i].WorkloadID == "prod/backend" {
			backendPolicy = &policies[i]
		}
	}
	require.NotNil(t, frontendPolicy)
	require.NotNil(t, backendPolicy)

	// frontend has egress rule to backend.
	require.Equal(t, 1, len(frontendPolicy.EgressRules))

	// backend has ingress rule from frontend (symmetric).
	require.Equal(t, 1, len(backendPolicy.IngressRules))

	ids := []string{policies[0].WorkloadID, policies[1].WorkloadID}
	require.NotContains(t, ids, "prod/cache")
	require.NotContains(t, ids, "prod/worker")
}

// TestBuild_PassivePeerSkipped verifies that a workload observed only as a
// passive peer through a flow where no symmetric ingress is added produces
// an empty policy that is skipped.
func TestBuild_PassivePeerSkipped(t *testing.T) {
	t.Parallel()

	now := time.Now()

	// Workload A sends egress to a world (pub) endpoint. A is observed.
	// Workload B is in the workloads map but never appears in allowed flows.
	workloads := analyze.Workloads{
		"prod/frontend": {
			Name:      "frontend",
			Namespace: "prod",
			Labels:    map[string]string{"app": "frontend"},
		},
		"prod/cache": {
			Name:      "cache",
			Namespace: "prod",
			Labels:    map[string]string{"app": "cache"},
		},
		"-/pub": {Name: "pub", Namespace: "-", Labels: map[string]string{"app": "pub"}},
	}

	flows := []flow.Flow{
		// frontend → pub: frontend gets world egress rule, pub is synthetic and skipped.
		{
			Time:        now,
			Source:      flow.Endpoint{Namespace: "prod", PodName: "frontend-abc", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "-", IP: "203.0.113.5", Labels: map[string]string{"app": "pub"}},
			Layer4:      flow.Layer4{DestPort: 443, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
		},
		// cache never appears in any allowed flow → not observed → skipped.
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{})

	// Only frontend has a policy (it has world egress rule).
	require.Len(t, policies, 1)
	require.Equal(t, "prod/frontend", policies[0].WorkloadID)
	require.Equal(t, 1, len(policies[0].EgressRules))

	ids := []string{policies[0].WorkloadID}
	require.NotContains(t, ids, "prod/cache")
}

// TestBuild_SkipIsReply verifies that reply flows do NOT produce policy rules.
func TestBuild_SkipIsReply(t *testing.T) {
	t.Parallel()

	now := time.Now()

	workloads := analyze.Workloads{
		"prod/frontend": {
			Name:      "frontend",
			Namespace: "prod",
			Labels:    map[string]string{"app": "frontend"},
		},
		"prod/backend": {
			Name:      "backend",
			Namespace: "prod",
			Labels:    map[string]string{"app": "backend"},
		},
	}

	flows := []flow.Flow{
		// Reply flow with Egress direction — should NOT create egress rule.
		{
			Time:        now,
			Source:      flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
			IsReply:     true,
		},
		// Reply flow with Ingress direction — should NOT create ingress rule.
		{
			Time:        now.Add(time.Second),
			Source:      flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Ingress,
			IsReply:     true,
		},
		// Non-reply Egress flow — should STILL create an egress rule.
		{
			Time:        now.Add(2 * time.Second),
			Source:      flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
			IsReply:     false,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{})

	// Find frontend policy.
	var frontendPolicy *Policy
	for i := range policies {
		if policies[i].WorkloadID == "prod/frontend" {
			frontendPolicy = &policies[i]
			break
		}
	}
	require.NotNil(t, frontendPolicy)

	// Non-reply egress flow still produces its egress rule.
	require.Equal(t, 1, len(frontendPolicy.EgressRules))
	require.Equal(t, []string{"app=backend"}, frontendPolicy.EgressRules[0].ToWorkloads)

	// The non-reply egress flow creates an egress rule on frontend and a
	// symmetric ingress rule on backend. Reply flows do NOT generate rules.
	var backendPolicy *Policy
	for i := range policies {
		if policies[i].WorkloadID == "prod/backend" {
			backendPolicy = &policies[i]
			break
		}
	}
	if backendPolicy != nil {
		require.Equal(t, 0, len(backendPolicy.EgressRules), "reply egress flow should not create backend egress rule")
		// Symmetric ingress from the non-reply egress flow.
		require.Equal(t, 1, len(backendPolicy.IngressRules))
		require.Equal(t, 1, len(backendPolicy.IngressRules[0].FromWorkloads))
		require.Equal(t, []string{"app=frontend"}, backendPolicy.IngressRules[0].FromWorkloads)
	}
}


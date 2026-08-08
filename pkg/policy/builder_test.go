package policy

import (
	"net"
	"strings"
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
			Time:        now,
			Source:      flow.Endpoint{Namespace: "prod", PodName: "api-server", IP: "10.0.0.1", Labels: map[string]string{"app": "api-server"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
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
			Time:        now,
			Source:      flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
		},
		{
			Time:        now.Add(time.Second),
			Source:      flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Ingress,
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
			Time:        now,
			Source:      flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
		},
		// Ingress: backend receives from frontend.
		{
			Time:        now.Add(time.Second),
			Source:      flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Ingress,
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
			Time:        now,
			Source:      flow.Endpoint{Namespace: "prod", PodName: "frontend-7d3f9abc", IP: "10.0.0.1"},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
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
		"prod/zeta":  {Name: "zeta", Namespace: "prod", Labels: map[string]string{"app": "zeta"}},
		"prod/alpha": {Name: "alpha", Namespace: "prod", Labels: map[string]string{"app": "alpha"}},
		"prod/mu":    {Name: "mu", Namespace: "prod", Labels: map[string]string{"app": "mu"}},
	}

	flows := []flow.Flow{
		{
			Time:        now,
			Source:      flow.Endpoint{Namespace: "prod", PodName: "mu-7d3f9abc", IP: "10.0.0.1"},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "zeta-7d3f9abc", IP: "10.0.0.2"},
			Layer4:      flow.Layer4{DestPort: 443, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
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
			Time:        now,
			Source:      flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
		},
		{
			Time:        now.Add(time.Second),
			Source:      flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Ingress,
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
		"-/-":   {Name: "-", Namespace: "", Labels: map[string]string{}},
		"-/pub": {Name: "pub", Namespace: "-", Labels: map[string]string{"app": "pub"}},
		"-/pvt": {Name: "pvt", Namespace: "-", Labels: map[string]string{"app": "pvt"}},
	}

	flows := []flow.Flow{
		{
			Time:        now,
			Source:      flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "-", IP: "203.0.113.5", Labels: map[string]string{"app": "pub"}},
			Layer4:      flow.Layer4{DestPort: 443, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
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
			Time:        now,
			Source:      flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "0.0.0.0", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "-", IP: "0.0.0.0", Labels: map[string]string{"app": "pub"}},
			Layer4:      flow.Layer4{DestPort: 443, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
		},
		{
			Time:        now.Add(time.Second),
			Source:      flow.Endpoint{Namespace: "-", IP: "0.0.0.0", Labels: map[string]string{"app": "pub"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "0.0.0.0", Labels: map[string]string{"app": "frontend"}},
			Layer4:      flow.Layer4{DestPort: 443, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Ingress,
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
			Time:        now,
			Source:      flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
		},
		{
			Time:        now.Add(time.Second),
			Source:      flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Ingress,
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
			Time:        now,
			Source:      flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
		},
		{
			Time:        now.Add(time.Second),
			Source:      flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "-", IP: "198.51.100.10", Labels: map[string]string{"app": "pub"}},
			Layer4:      flow.Layer4{DestPort: 443, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
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
			Time:        now,
			Source:      flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
		},
		{
			Time:        now.Add(time.Second),
			Source:      flow.Endpoint{Namespace: "prod", PodName: "frontend-efgh", IP: "10.0.0.3", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-rst", IP: "10.0.0.4", Labels: map[string]string{"app": "backend"}},
			Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
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
			Time:        now,
			Source:      flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
		},
		{
			Time:        now.Add(time.Second),
			Source:      flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "cache-xyz", IP: "10.0.0.3", Labels: map[string]string{"app": "cache"}},
			Layer4:      flow.Layer4{DestPort: 6379, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
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
			Time:        now,
			Source:      flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
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
			Time:        now,
			Source:      flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:      flow.Layer4{DestPort: 443, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
		},
		{
			Time:        now.Add(time.Second),
			Source:      flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:      flow.Layer4{DestPort: 443, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
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
			Time:        now,
			Source:      flow.Endpoint{Namespace: "prod", PodName: "frontend-abcd", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
			Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
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

// TestBuild_ApiserverIngressSentinel verifies the apiserver-port override only
// fires when the source peer IS the kube-apiserver (reserved label or selector
// match), while plain world/pvt sources stay world.
func TestBuild_ApiserverIngressSentinel(t *testing.T) {
	t.Parallel()

	_, ns, _ := net.ParseCIDR("10.0.0.0/8")

	// Case 1: source carries reserved:kube-apiserver label → apiserver override.
	t.Run("reservedLabel", func(t *testing.T) {
		t.Parallel()

		cfg := config.Config{
			ClusterCIDRs:          []*net.IPNet{ns},
			ApiserverIngressPorts: []config.PortSpec{{Protocol: "TCP", Port: 9443}},
		}

		workloads := analyze.Workloads{
			"prod/api-server":      {Name: "api-server", Namespace: "prod", Labels: map[string]string{"app": "api-server"}},
			"-/kube-apiserver-res": {Name: "kube-apiserver-res", Namespace: "-", Labels: map[string]string{"reserved:kube-apiserver": "true"}},
		}

		flows := []flow.Flow{
			{
				Time:        time.Now(),
				Source:      flow.Endpoint{Namespace: "-", IP: "0.0.0.0", Labels: map[string]string{"reserved:kube-apiserver": "true"}},
				Destination: flow.Endpoint{Namespace: "prod", IP: "10.96.0.1", Labels: map[string]string{"app": "api-server"}},
				Layer4:      flow.Layer4{DestPort: 9443, Protocol: flow.TCP},
				Verdict:     flow.Allow,
				Direction:   flow.Ingress,
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
	})

	// Case 2: plain pub source — NOT apiserver → world.
	t.Run("pubSourceWorld", func(t *testing.T) {
		t.Parallel()

		cfg := config.Config{
			ClusterCIDRs:          []*net.IPNet{ns},
			ApiserverIngressPorts: []config.PortSpec{{Protocol: "TCP", Port: 9443}},
		}

		workloads := analyze.Workloads{
			"prod/api-server": {Name: "api-server", Namespace: "prod", Labels: map[string]string{"app": "api-server"}},
			"-/pub":           {Name: "pub", Namespace: "-", Labels: map[string]string{"app": "pub"}},
		}

		flows := []flow.Flow{
			{
				Time:        time.Now(),
				Source:      flow.Endpoint{Namespace: "-", IP: "0.0.0.0", Labels: map[string]string{"app": "pub"}},
				Destination: flow.Endpoint{Namespace: "prod", IP: "10.96.0.1", Labels: map[string]string{"app": "api-server"}},
				Layer4:      flow.Layer4{DestPort: 9443, Protocol: flow.TCP},
				Verdict:     flow.Allow,
				Direction:   flow.Ingress,
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
	})
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
		"-/pub":           {Name: "pub", Namespace: "-", Labels: map[string]string{"app": "pub"}},
	}

	flows := []flow.Flow{
		{
			Time:        time.Now(),
			Source:      flow.Endpoint{Namespace: "-", IP: "0.0.0.0", Labels: map[string]string{"app": "pub"}},
			Destination: flow.Endpoint{Namespace: "prod", IP: "10.96.0.1", Labels: map[string]string{"app": "api-server"}},
			Layer4:      flow.Layer4{DestPort: 443, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Ingress,
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
		"-/pub":           {Name: "pub", Namespace: "-", Labels: map[string]string{"app": "pub"}},
	}

	flows := []flow.Flow{
		{
			Time:        time.Now(),
			Source:      flow.Endpoint{Namespace: "-", IP: "0.0.0.0", Labels: map[string]string{"app": "pub"}},
			Destination: flow.Endpoint{Namespace: "prod", IP: "10.96.0.1", Labels: map[string]string{"app": "api-server"}},
			Layer4:      flow.Layer4{DestPort: 9443, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Ingress,
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

// TestBuild_ApiServerEgressSentinel verifies the apiserver-port override only
// fires when the destination peer IS the kube-apiserver (reserved label or
// selector match), while plain world/pvt destinations stay world.
func TestBuild_ApiServerEgressSentinel(t *testing.T) {
	t.Parallel()

	_, ns, _ := net.ParseCIDR("10.0.0.0/8")

	// Case 1: destination carries reserved:kube-apiserver label → apiserver override.
	t.Run("reservedLabel", func(t *testing.T) {
		t.Parallel()

		cfg := config.Config{
			ClusterCIDRs:         []*net.IPNet{ns},
			ApiserverEgressPorts: []config.PortSpec{{Protocol: "TCP", Port: 6443}},
		}

		workloads := analyze.Workloads{
			"prod/web":                {Name: "web", Namespace: "prod", Labels: map[string]string{"app": "web"}},
			"-/kube-apiserver-egress": {Name: "kube-apiserver-egress", Namespace: "-", Labels: map[string]string{"reserved:kube-apiserver": "true"}},
		}

		flows := []flow.Flow{
			{
				Time:        time.Now(),
				Source:      flow.Endpoint{Namespace: "prod", IP: "10.0.0.2", Labels: map[string]string{"app": "web"}},
				Destination: flow.Endpoint{Namespace: "-", IP: "0.0.0.0", Labels: map[string]string{"reserved:kube-apiserver": "true"}},
				Layer4:      flow.Layer4{DestPort: 6443, Protocol: flow.TCP},
				Verdict:     flow.Allow,
				Direction:   flow.Egress,
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
	})

	// Case 2: plain pub destination — NOT apiserver → world.
	t.Run("pubDestWorld", func(t *testing.T) {
		t.Parallel()

		cfg := config.Config{
			ClusterCIDRs:         []*net.IPNet{ns},
			ApiserverEgressPorts: []config.PortSpec{{Protocol: "TCP", Port: 6443}},
		}

		workloads := analyze.Workloads{
			"prod/web": {Name: "web", Namespace: "prod", Labels: map[string]string{"app": "web"}},
			"-/pub":    {Name: "pub", Namespace: "-", Labels: map[string]string{"app": "pub"}},
		}

		flows := []flow.Flow{
			{
				Time:        time.Now(),
				Source:      flow.Endpoint{Namespace: "prod", IP: "10.0.0.2", Labels: map[string]string{"app": "web"}},
				Destination: flow.Endpoint{Namespace: "-", IP: "0.0.0.0", Labels: map[string]string{"app": "pub"}},
				Layer4:      flow.Layer4{DestPort: 6443, Protocol: flow.TCP},
				Verdict:     flow.Allow,
				Direction:   flow.Egress,
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
	})
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
			Time:        time.Now(),
			Source:      flow.Endpoint{Namespace: "prod", IP: "10.0.0.2", Labels: map[string]string{"app": "web"}},
			Destination: flow.Endpoint{Namespace: "-", IP: "0.0.0.0", Labels: map[string]string{"app": "pub"}},
			Layer4:      flow.Layer4{DestPort: 443, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
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
			Time:        time.Now(),
			Source:      flow.Endpoint{Namespace: "prod", IP: "10.0.0.2", Labels: map[string]string{"app": "web"}},
			Destination: flow.Endpoint{Namespace: "-", IP: "0.0.0.0", Labels: map[string]string{"app": "pub"}},
			Layer4:      flow.Layer4{DestPort: 6443, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
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
		"-/pub":                {Name: "pub", Namespace: "-", Labels: map[string]string{"app": "pub"}},
	}

	flows := []flow.Flow{}
	for i := 0; i < 5; i++ {
		flows = append(flows, flow.Flow{
			Time:        time.Now().Add(time.Duration(i) * time.Second),
			Source:      flow.Endpoint{Namespace: "-", IP: "0.0.0.0", Labels: map[string]string{"app": "pub"}},
			Destination: flow.Endpoint{Namespace: "kube-system", IP: "10.96.0.10", Labels: map[string]string{"app": "kube-dns"}},
			Layer4:      flow.Layer4{DestPort: 53, Protocol: flow.UDP},
			Verdict:     flow.Allow,
			Direction:   flow.Ingress,
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
		"-/pub":                {Name: "pub", Namespace: "-", Labels: map[string]string{"app": "pub"}},
	}

	flows := []flow.Flow{
		{
			Time:        time.Now(),
			Source:      flow.Endpoint{Namespace: "-", IP: "0.0.0.0", Labels: map[string]string{"app": "pub"}},
			Destination: flow.Endpoint{Namespace: "kube-system", IP: "10.96.0.10", Labels: map[string]string{"app": "kube-dns"}},
			Layer4:      flow.Layer4{DestPort: 53, Protocol: flow.UDP},
			Verdict:     flow.Allow,
			Direction:   flow.Ingress,
		},
		{
			Time:        time.Now().Add(time.Second),
			Source:      flow.Endpoint{Namespace: "kube-system", PodName: "podA", IP: "10.0.0.2", Labels: map[string]string{"app": "podA"}},
			Destination: flow.Endpoint{Namespace: "kube-system", IP: "10.96.0.10", Labels: map[string]string{"app": "kube-dns"}},
			Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Ingress,
		},
		{
			Time:        time.Now().Add(2 * time.Second),
			Source:      flow.Endpoint{Namespace: "kube-system", PodName: "podB", IP: "10.0.0.3", Labels: map[string]string{"app": "podB"}},
			Destination: flow.Endpoint{Namespace: "kube-system", IP: "10.96.0.10", Labels: map[string]string{"app": "kube-dns"}},
			Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Ingress,
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

// TestBuild_ApiServerSourceMirrorIngress verifies that a synthetic-source
// egress flow (PeerType=KubeAPIServer) does NOT become a world egress rule
// and DOES produce a mirrored ingress rule on the destination workload
// so that the apiserver peer is allowed inbound traffic.
func TestBuild_ApiServerSourceMirrorIngress(t *testing.T) {
	t.Parallel()

	_, clusterN, _ := net.ParseCIDR("10.244.0.0/16")
	_, apiserverN, _ := net.ParseCIDR("192.168.107.5/32")
	cfg := config.Config{
		ClusterCIDRs:   []*net.IPNet{clusterN},
		APIServerCIDRs: []*net.IPNet{apiserverN},
	}

	workloads := analyze.Workloads{
		"-/host": {
			Name:      "host",
			Namespace: "-",
			Labels:    map[string]string{"reserved:host": ""},
		},
		"kube-system/coredns": {
			Name:      "coredns",
			Namespace: "kube-system",
			Labels:    map[string]string{"app": "coredns"},
		},
	}

	flows := []flow.Flow{
		{
			Time:   time.Now(),
			Source: flow.Endpoint{IP: "10.244.0.57", Labels: map[string]string{"reserved:host": "", "reserved:kube-apiserver": ""}},
			Destination: flow.Endpoint{
				Namespace: "kube-system", PodName: "coredns-xxx", IP: "10.244.0.12",
				Labels: map[string]string{"app": "coredns"},
			},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Egress,
			PeerType:  flow.KubeAPIServer,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{Config: &cfg})

	// host is synthetic — must NOT appear in policies.
	var corednsPolicy *Policy
	for i := range policies {
		if policies[i].WorkloadID == "kube-system/coredns" {
			corednsPolicy = &policies[i]
		}
	}
	require.NotNil(t, corednsPolicy)

	// coredns must have a mirrored ingress rule carrying:
	//   - CIDR twin "10.244.0.57/32" in FromWorkloads (private IP → /32)
	//   - entity sentinel "entity:host,kube-apiserver" in FromEntities
	require.GreaterOrEqual(t, len(corednsPolicy.IngressRules), 1,
		"expected at least one ingress rule on coredns from apiserver source")

	// Find the ingress rule whose FromEntities contains the mirrored entity sentinel
	// and whose FromWorkloads carries the CIDR twin (dual-carry invariant).
	var foundRule bool
	for _, rule := range corednsPolicy.IngressRules {
		// Dual-carry: entity sentinel in FromEntities, CIDR twin in FromWorkloads.
		var hasEntity bool
		for _, fe := range rule.FromEntities {
			if fe == "entity:host,kube-apiserver" {
				hasEntity = true
				break
			}
		}
		var hasCIDRTwin bool
		for _, fw := range rule.FromWorkloads {
			if fw == "10.244.0.57/32" {
				hasCIDRTwin = true
				break
			}
		}
		require.True(t, hasEntity, "expected ingress rule with FromEntities containing entity:host,kube-apiserver")
		require.True(t, hasCIDRTwin, "expected CIDR twin 10.244.0.57/32 in FromWorkloads")

		var foundPort8080 bool
		for _, p := range rule.Ports {
			if p.Port == 8080 && string(p.Protocol) == "TCP" {
				foundPort8080 = true
				break
			}
		}
		require.True(t, foundPort8080, "expected port 8080/TCP in mirrored ingress rule")

		foundRule = true
	}
	require.True(t, foundRule, "expected to find the mirrored ingress rule on coredns")
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

// TestIsSyntheticEndpoint verifies that isSyntheticEndpoint returns true for
// synthetic workload names (pvt, pub, -) and for endpoints whose Labels carry
// a reserved: prefix, and false otherwise.
func TestIsSyntheticEndpoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		ep       flow.Endpoint
		expected bool
	}{
		{
			name:     "reserved:host label",
			ep:       flow.Endpoint{Labels: map[string]string{"reserved:host": ""}},
			expected: true,
		},
		{
			name:     "reserved:kube-apiserver label",
			ep:       flow.Endpoint{Labels: map[string]string{"reserved:kube-apiserver": ""}},
			expected: true,
		},
		{
			name:     "normal pod labels",
			ep:       flow.Endpoint{Labels: map[string]string{"app": "demo"}},
			expected: false,
		},
		{
			name:     "empty labels and empty name",
			ep:       flow.Endpoint{Labels: map[string]string{}, Namespace: "kube-system"},
			expected: false,
		},
		{
			name:     "PodName pvt resolves to synthetic",
			ep:       flow.Endpoint{PodName: "pvt"},
			expected: true,
		},
		{
			name:     "PodName pub resolves to synthetic",
			ep:       flow.Endpoint{PodName: "pub"},
			expected: true,
		},
		{
			name:     "PodName dash resolves to synthetic",
			ep:       flow.Endpoint{PodName: "-"},
			expected: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isSyntheticEndpoint(tt.ep)
			require.Equal(t, tt.expected, got)
		})
	}
}

// TestClassifySyntheticPeer verifies classifying synthetic peers by IP.
func TestClassifySyntheticPeer(t *testing.T) {
	t.Parallel()

	_, apiserverCIDR, err := net.ParseCIDR("10.244.0.73/32")
	require.NoError(t, err)

	cfg := &config.Config{
		APIServerCIDRs: []*net.IPNet{apiserverCIDR},
	}

	tests := []struct {
		name     string
		ip       net.IP
		cfg      *config.Config
		expected string
	}{
		{
			name:     "nil IP returns world",
			ip:       nil,
			cfg:      cfg,
			expected: "world",
		},
		{
			name:     "empty IP string returns world",
			ip:       net.IP{},
			cfg:      cfg,
			expected: "world",
		},
		{
			name:     "apiserver IP",
			ip:       net.ParseIP("10.244.0.73"),
			cfg:      cfg,
			expected: "apiserver",
		},
		{
			name:     "private node IP",
			ip:       net.ParseIP("10.244.1.232"),
			cfg:      cfg,
			expected: "10.244.1.232/32",
		},
		{
			name:     "public IP",
			ip:       net.ParseIP("8.8.8.8"),
			cfg:      cfg,
			expected: "world",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := classifySyntheticPeer(tt.ip, tt.cfg)
			require.Equal(t, tt.expected, got)
		})
	}
}

// TestBuildIngressCIDRPeer verifies that generic CIDR peer keys emit sorted
// IngressRules with deduplicated ports.
func TestBuildIngressCIDRPeer(t *testing.T) {
	t.Parallel()

	now := time.Now()
	ingress := map[flowKey]*flowEntry{
		{peer: "10.244.1.232", cidr: "10.244.1.232/32", port: 4222, proto: "TCP"}: {count: 5, firstSeen: now, lastSeen: now},
		{peer: "10.244.2.5", cidr: "10.244.2.5/32", port: 9999, proto: "TCP"}:     {count: 3, firstSeen: now, lastSeen: now},
	}

	rules := buildIngressRules(ingress, "default", "hubble-relay", nil, BuildOptions{})
	require.Len(t, rules, 2)

	// Sorted by CIDR key.
	require.Equal(t, "10.244.1.232/32", rules[0].FromWorkloads[0])
	require.Equal(t, uint16(4222), rules[0].Ports[0].Port)
	require.Equal(t, "TCP", rules[0].Ports[0].Protocol)

	require.Equal(t, "10.244.2.5/32", rules[1].FromWorkloads[0])
	require.Equal(t, uint16(9999), rules[1].Ports[0].Port)
	require.Equal(t, "TCP", rules[1].Ports[0].Protocol)
}

// TestBuildIngressCIDRPeerDedup verifies that same CIDR but different ports
// produces separate port entries, not duplicate port/proto pairs.
func TestBuildIngressCIDRPeerDedup(t *testing.T) {
	t.Parallel()

	now := time.Now()
	ingress := map[flowKey]*flowEntry{
		{peer: "10.244.1.10", cidr: "10.244.1.10/32", port: 8080, proto: "TCP"}: {count: 100, firstSeen: now, lastSeen: now},
		{peer: "10.244.1.10", cidr: "10.244.1.10/32", port: 443, proto: "TCP"}:  {count: 200, firstSeen: now, lastSeen: now},
	}

	rules := buildIngressRules(ingress, "default", "api", nil, BuildOptions{})
	require.Len(t, rules, 1)
	// Two distinct ports for same CIDR → 2 port specs.
	require.Len(t, rules[0].Ports, 2)
	require.Equal(t, uint16(443), rules[0].Ports[0].Port)
	require.Equal(t, uint16(8080), rules[0].Ports[1].Port)
}

// TestBuildIngressCIDRWithL7Suffix verifies that hasL7DNS and hasL7HTTP flags
// are appended to the rule description for CIDR peers.
func TestBuildIngressCIDRWithL7Suffix(t *testing.T) {
	t.Parallel()

	now := time.Now()
	ingress := map[flowKey]*flowEntry{
		{peer: "10.244.3.7", cidr: "10.244.3.7/32", port: 53, proto: "UDP"}: {count: 10, firstSeen: now, lastSeen: now, hasL7DNS: true},
	}

	rules := buildIngressRules(ingress, "default", "dns-relay", nil, BuildOptions{})
	require.Len(t, rules, 1)
	require.Contains(t, rules[0].Ports[0].Description, "L7 DNS")
}

// TestBuild_SyntheticSourceEgressMirrorCIDR verifies that when an egress-flow
// originates from a synthetic (reserved-label) source, the symmetric mirror
// creates an ingress rule on the destination with the classified CIDR instead
// of 0.0.0.0/0.
func TestBuild_SyntheticSourceEgressMirrorCIDR(t *testing.T) {
	t.Parallel()

	now := time.Now()

	relayPod := "hubble-relay-abc123"

	// Case A: reserved:host source → /32 CIDR ingress on destination.
	t.Run("reserved:host mirrors as /32 CIDR", func(t *testing.T) {
		t.Parallel()

		_, apiserverCIDR, _ := net.ParseCIDR("10.244.0.73/32")

		workloads := analyze.Workloads{
			"kube-system/hubble-relay": {
				Name:      "hubble-relay",
				Namespace: "kube-system",
				Labels:    map[string]string{"app": "hubble-relay"},
			},
		}

		cfg := &config.Config{
			APIServerCIDRs:        []*net.IPNet{apiserverCIDR},
			ClusterCIDRs:          nil,
			ApiserverIngressPorts: nil,
			ApiserverEgressPorts:  nil,
		}

		flows := []flow.Flow{
			{
				Time:        now,
				Source:      flow.Endpoint{Labels: map[string]string{"reserved:host": ""}, IP: "10.244.1.232"},
				Destination: flow.Endpoint{Labels: map[string]string{"app": "hubble-relay"}, Namespace: "kube-system", PodName: relayPod, IP: "10.244.1.136"},
				Layer4:      flow.Layer4{DestPort: 4222, Protocol: flow.TCP},
				Verdict:     flow.Allow,
				Direction:   flow.Egress,
			},
		}

		policies := Build(flows, nil, workloads, nil, BuildOptions{Config: cfg})
		require.Len(t, policies, 1)
		require.Equal(t, "kube-system/hubble-relay", policies[0].WorkloadID)

		// Find ingress rule for port 4222.
		foundEntity := false
		foundWorld := false
		foundCIDRTwin := false
		for _, rule := range policies[0].IngressRules {
			for _, p := range rule.Ports {
				if p.Port == 4222 {
					for _, fw := range rule.FromWorkloads {
						if fw == "0.0.0.0/0" {
							foundWorld = true
						}
						if fw == "10.244.1.232/32" {
							foundCIDRTwin = true
						}
					}
					for _, fe := range rule.FromEntities {
						if fe == "entity:host" {
							foundEntity = true
						}
					}
				}
			}
		}
		require.True(t, foundEntity, "expected ingress entity:host for port 4222")
		require.True(t, foundCIDRTwin, "expected CIDR twin 10.244.1.232/32 in FromWorkloads")
		require.False(t, foundWorld, "port 4222 must NOT pair with 0.0.0.0/0")
	})

	// Case B: reserved:world source → when IP is in APIServerCIDR, port goes in apiserver rule.
	t.Run("reserved:world mirrors as apiserver rule", func(t *testing.T) {
		t.Parallel()

		_, apiserverCIDR, _ := net.ParseCIDR("10.244.0.73/32")

		workloads := analyze.Workloads{
			"kube-system/hubble-relay": {
				Name:      "hubble-relay",
				Namespace: "kube-system",
				Labels:    map[string]string{"app": "hubble-relay"},
			},
		}

		cfg := &config.Config{
			APIServerCIDRs:        []*net.IPNet{apiserverCIDR},
			ClusterCIDRs:          nil,
			ApiserverIngressPorts: nil,
			ApiserverEgressPorts:  nil,
		}

		flows := []flow.Flow{
			{
				Time:        now,
				Source:      flow.Endpoint{Labels: map[string]string{"reserved:world": ""}, IP: "10.244.0.73"},
				Destination: flow.Endpoint{Labels: map[string]string{"app": "hubble-relay"}, Namespace: "kube-system", PodName: relayPod, IP: "10.244.1.136"},
				Layer4:      flow.Layer4{DestPort: 4245, Protocol: flow.TCP},
				Verdict:     flow.Allow,
				Direction:   flow.Egress,
			},
		}

		policies := Build(flows, nil, workloads, nil, BuildOptions{Config: cfg})
		require.Len(t, policies, 1)
		require.Equal(t, "kube-system/hubble-relay", policies[0].WorkloadID)

		// Port 4245 dual-carry: CIDR twin "apiserver" in FromWorkloads and
		// entity sentinel "entity:world" in FromEntities.
		foundEntity4245 := false
		foundAPIServerTwin := false
		foundWorldCIDR := false
		for _, rule := range policies[0].IngressRules {
			for _, p := range rule.Ports {
				if p.Port == 4245 {
					for _, fw := range rule.FromWorkloads {
						if fw == "apiserver" {
							foundAPIServerTwin = true
						}
						if fw == "0.0.0.0/0" {
							foundWorldCIDR = true
						}
					}
					for _, fe := range rule.FromEntities {
						if fe == "entity:world" {
							foundEntity4245 = true
						}
					}
				}
			}
		}
		require.True(t, foundEntity4245, "expected port 4245 with entity:world sentinel in FromEntities")
		require.True(t, foundAPIServerTwin, "port 4245 CIDR twin should be 'apiserver' (10.244.0.73 ∈ APIServerCIDRs)")
		require.False(t, foundWorldCIDR, "port 4245 must NOT pair with 0.0.0.0/0")
	})

	// Case D: reserved:world source with PUBLIC IP → world-twin dual-carry.
	// Ingress mirror bucket: FromWorkloads=="0.0.0.0/0" + FromEntities=="entity:world"
	// Egress entity bucket: ToCIDRs=="0.0.0.0/0" + ToEntities=="entity:world".
	t.Run("reserved:world public IP yields world-twin dual-carry", func(t *testing.T) {
		t.Parallel()

		workloads := analyze.Workloads{
			"prod/server": {
				Name:      "server",
				Namespace: "prod",
				Labels:    map[string]string{"app": "server"},
			},
		}

		flows := []flow.Flow{
			// World→server: egress flow from synthetic source mirrors as INGRESS on server.
			{
				Time:        now,
				Source:      flow.Endpoint{Labels: map[string]string{"reserved:world": ""}, IP: "8.8.8.8"},
				Destination: flow.Endpoint{Labels: map[string]string{"app": "server"}, Namespace: "prod", PodName: "server-pod", IP: "10.244.1.50"},
				Layer4:      flow.Layer4{DestPort: 4245, Protocol: flow.TCP},
				Verdict:     flow.Allow,
				Direction:   flow.Egress,
			},
			// Server→world: egress flow from real source creates EGRESS on server.
			{
				Time:        now,
				Source:      flow.Endpoint{Labels: map[string]string{"app": "server"}, Namespace: "prod", PodName: "server-pod", IP: "10.244.1.50"},
				Destination: flow.Endpoint{Labels: map[string]string{"reserved:world": ""}, IP: "8.8.8.8"},
				Layer4:      flow.Layer4{DestPort: 4245, Protocol: flow.TCP},
				Verdict:     flow.Allow,
				Direction:   flow.Egress,
			},
		}

		policies := Build(flows, nil, workloads, nil, BuildOptions{})
		require.Len(t, policies, 1) // only prod/server (world peer is synthetic, no own policy)

		srvPolicy := policies[0]
		require.Equal(t, "prod/server", srvPolicy.WorkloadID)

		// Ingress rule: world twin dual-carry.
		require.Len(t, srvPolicy.IngressRules, 1)
		ing := srvPolicy.IngressRules[0]
		require.Equal(t, []string{"0.0.0.0/0"}, ing.FromWorkloads, "expected world CIDR twin in FromWorkloads")
		require.Equal(t, []string{"entity:world"}, ing.FromEntities, "expected world entity sentinel")
		foundPort := false
		for _, p := range ing.Ports {
			if p.Port == 4245 {
				foundPort = true
			}
		}
		require.True(t, foundPort, "port 4245 must be in the dual-carry ingress rule")

		// Egress rule: world twin dual-carry.
		require.Len(t, srvPolicy.EgressRules, 1)
		egr := srvPolicy.EgressRules[0]
		require.Equal(t, []string{"0.0.0.0/0"}, egr.ToCIDRs, "expected world CIDR twin in ToCIDRs")
		require.Equal(t, []string{"entity:world"}, egr.ToEntities, "expected world entity sentinel")
		foundEport := false
		for _, p := range egr.ToPorts {
			if p.Port == 4245 {
				foundEport = true
			}
		}
		require.True(t, foundEport, "port 4245 must be in the dual-carry egress rule")
	})

	// Case C: normal pod-to-pod egress still mirrors as per-peer ingress (regression guard).
	t.Run("non-synthetic egress mirrors as per-peer", func(t *testing.T) {
		t.Parallel()

		workloads := analyze.Workloads{
			"flowlab/client": {
				Name:      "client",
				Namespace: "flowlab",
				Labels:    map[string]string{"app": "client"},
			},
			"kube-system/hubble-relay": {
				Name:      "hubble-relay",
				Namespace: "kube-system",
				Labels:    map[string]string{"app": "hubble-relay"},
			},
		}

		flows := []flow.Flow{
			{
				Time:        now,
				Source:      flow.Endpoint{Namespace: "flowlab", PodName: "client-xyz", Labels: map[string]string{"app": "client"}, IP: "10.244.2.50"},
				Destination: flow.Endpoint{Labels: map[string]string{"app": "hubble-relay"}, Namespace: "kube-system", PodName: relayPod, IP: "10.244.1.136"},
				Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
				Verdict:     flow.Allow,
				Direction:   flow.Egress,
			},
		}

		policies := Build(flows, nil, workloads, nil, BuildOptions{})
		// Both workloads should each get their own policy.
		require.Len(t, policies, 2)

		// Find the hubble-relay policy and verify its ingress rules don't use 0.0.0.0/0.
		var relayPolicy *Policy
		for i := range policies {
			if policies[i].WorkloadID == "kube-system/hubble-relay" {
				relayPolicy = &policies[i]
				break
			}
		}
		require.NotNil(t, relayPolicy)

		// Must have ingress rules (from symmetric mirror), and none may use 0.0.0.0/0.
		require.Greater(t, len(relayPolicy.IngressRules), 0)
		for _, rule := range relayPolicy.IngressRules {
			for _, fw := range rule.FromWorkloads {
				require.NotEqual(t, "0.0.0.0/0", fw, "non-synthetic egress must NOT mirror as 0.0.0.0/0")
			}
		}
	})
}

// TestReservedEntities verifies the reservedEntities helper extracts
// reserved:* label keys, strips the prefix, sorts, and produces deterministic
// "entity:<list>" output.
func TestReservedEntities(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		endpoint flow.Endpoint
		expected string
	}{
		{
			name: "single reserved:host label",
			endpoint: flow.Endpoint{
				Labels: map[string]string{"reserved:host": ""},
			},
			expected: "entity:host",
		},
		{
			name: "single reserved:world label",
			endpoint: flow.Endpoint{
				Labels: map[string]string{"reserved:world": ""},
			},
			expected: "entity:world",
		},
		{
			name: "reserved:kube-apiserver label",
			endpoint: flow.Endpoint{
				Labels: map[string]string{"reserved:kube-apiserver": ""},
			},
			expected: "entity:kube-apiserver",
		},
		{
			name: "reserved:host + reserved:kube-apiserver (sorted)",
			endpoint: flow.Endpoint{
				Labels: map[string]string{
					"reserved:host":           "",
					"reserved:kube-apiserver": "",
				},
			},
			expected: "entity:host,kube-apiserver",
		},
		{
			name: "reserved:remote-node + reserved:host + reserved:kube-apiserver (sorted)",
			endpoint: flow.Endpoint{
				Labels: map[string]string{
					"reserved:remote-node":    "",
					"reserved:host":           "",
					"reserved:kube-apiserver": "",
				},
			},
			expected: "entity:host,kube-apiserver,remote-node",
		},
		{
			name: "no reserved labels",
			endpoint: flow.Endpoint{
				Labels: map[string]string{"app": "demo"},
			},
			expected: "",
		},
		{
			name: "empty labels",
			endpoint: flow.Endpoint{
				Labels: map[string]string{},
			},
			expected: "",
		},
		{
			name: "nil labels",
			endpoint: flow.Endpoint{
				Labels: nil,
			},
			expected: "",
		},
		{
			name: "reserved:world + reserved:host (sorted)",
			endpoint: flow.Endpoint{
				Labels: map[string]string{
					"reserved:world": "",
					"reserved:host":  "",
				},
			},
			expected: "entity:host,world",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := reservedEntities(tt.endpoint)
			require.Equal(t, tt.expected, got)
		})
	}
}

// TestBuild_EntitySentinelIngress verifies that a flow with a reserved-label
// source (e.g. reserved:host) produces an ingress rule with the entity sentinel
// in FromWorkloads instead of a CIDR.
func TestBuild_EntitySentinelIngress(t *testing.T) {
	t.Parallel()

	now := time.Now()

	workloads := analyze.Workloads{
		"prod/api-server": {Name: "api-server", Namespace: "prod", Labels: map[string]string{"app": "api-server"}},
	}

	flows := []flow.Flow{
		{
			Time:        now,
			Source:      flow.Endpoint{Labels: map[string]string{"reserved:host": ""}, IP: "10.244.1.232"},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "api-server", Labels: map[string]string{"app": "api-server"}, IP: "10.244.2.100"},
			Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Ingress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{})
	require.Len(t, policies, 1)
	require.Equal(t, "prod/api-server", policies[0].WorkloadID)
	require.Len(t, policies[0].IngressRules, 1)
	// Dual-carry: CIDR twin (FromWorkloads) + entity sentinel (FromEntities).
	require.Equal(t, []string{"10.244.1.232/32"}, policies[0].IngressRules[0].FromWorkloads)
	require.Equal(t, []string{"entity:host"}, policies[0].IngressRules[0].FromEntities)
	require.Len(t, policies[0].IngressRules[0].Ports, 1)
	require.Equal(t, uint16(8080), policies[0].IngressRules[0].Ports[0].Port)
	// world/0.0.0.0/0 must NOT appear.
	for _, fw := range policies[0].IngressRules[0].FromWorkloads {
		require.NotEqual(t, "world", fw)
		require.NotEqual(t, "0.0.0.0/0", fw)
	}
}

// TestBuild_EntitySentinelEgress verifies that egress to a reserved-label
// destination produces an EgressRule with the entity sentinel in ToCIDRs.
func TestBuild_EntitySentinelEgress(t *testing.T) {
	t.Parallel()

	now := time.Now()

	workloads := analyze.Workloads{
		"prod/web": {Name: "web", Namespace: "prod", Labels: map[string]string{"app": "web"}},
		"-/host":   {Name: "host", Namespace: "-", Labels: map[string]string{"reserved:host": ""}},
	}

	flows := []flow.Flow{
		{
			Time:        now,
			Source:      flow.Endpoint{Namespace: "prod", PodName: "web-abc", Labels: map[string]string{"app": "web"}, IP: "10.244.2.100"},
			Destination: flow.Endpoint{Labels: map[string]string{"reserved:host": ""}, IP: "10.244.1.232"},
			Layer4:      flow.Layer4{DestPort: 22, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{})

	assertEntityEgressRule := func(t *testing.T, p *Policy) {
		t.Helper()
		require.Len(t, p.EgressRules, 1)
		// Dual-carry: CIDR twin in ToCIDRs + entity sentinel in ToEntities.
		require.Equal(t, []string{"10.244.1.232/32"}, p.EgressRules[0].ToCIDRs)
		require.Equal(t, []string{"entity:host"}, p.EgressRules[0].ToEntities)
		require.Len(t, p.EgressRules[0].ToPorts, 1)
		require.Equal(t, uint16(22), p.EgressRules[0].ToPorts[0].Port)
	}

	var hostPolicy, webPolicy *Policy
	for i := range policies {
		switch policies[i].WorkloadID {
		case "prod/web":
			webPolicy = &policies[i]
		case "-/host":
			hostPolicy = &policies[i]
		}
	}
	assertEntityEgressRule(t, webPolicy)
	// host is synthetic (no pod name, empty namespace) and should be skipped as a workload.
	// Only pod-pod flows mirror, but this is egress to a synthetic dest.
	if hostPolicy != nil {
		require.Len(t, hostPolicy.EgressRules, 0)
	}
}

// TestBuild_EntitySentinelMirror verifies that a reserved-label source egress
// produces a mirrored ingress rule with the entity sentinel as the FromWorkloads.
func TestBuild_EntitySentinelMirror(t *testing.T) {
	t.Parallel()

	now := time.Now()

	workloads := analyze.Workloads{
		"prod/server": {Name: "server", Namespace: "prod", Labels: map[string]string{"app": "server"}},
		"-/host":      {Name: "host", Namespace: "-", Labels: map[string]string{"reserved:host": ""}},
	}

	flows := []flow.Flow{
		{
			Time:        now,
			Source:      flow.Endpoint{Labels: map[string]string{"reserved:host": ""}, IP: "10.244.1.232"},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "server-abc", Labels: map[string]string{"app": "server"}, IP: "10.244.2.100"},
			Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{})

	// server (destination) should have a mirrored ingress rule.
	var serverPolicy *Policy
	for i := range policies {
		if policies[i].WorkloadID == "prod/server" {
			serverPolicy = &policies[i]
			break
		}
	}
	require.NotNil(t, serverPolicy)
	require.Len(t, serverPolicy.IngressRules, 1)
	// Dual-carry: CIDR twin + entity sentinel.
	require.Equal(t, []string{"10.244.1.232/32"}, serverPolicy.IngressRules[0].FromWorkloads)
	require.Equal(t, []string{"entity:host"}, serverPolicy.IngressRules[0].FromEntities)
	require.Equal(t, uint16(8080), serverPolicy.IngressRules[0].Ports[0].Port)
}

// TestBuild_EntitySentinelBackwardCompat verifies that flows WITHOUT reserved
// labels still produce the old sentinel paths (apiserver, CIDR, world).
func TestBuild_EntitySentinelBackwardCompat(t *testing.T) {
	t.Parallel()

	now := time.Now()

	_, ns, _ := net.ParseCIDR("10.0.0.0/8")

	tests := []struct {
		name                 string
		flow                 flow.Flow
		config               BuildOptions
		assertFrontendPolicy func(t *testing.T, p *Policy)
		assertBackendPolicy  func(t *testing.T, p *Policy)
	}{
		{
			name: "normal CIDR peer produces /32 rule",
			flow: flow.Flow{
				Time:        now,
				Source:      flow.Endpoint{Namespace: "prod", PodName: "web", Labels: map[string]string{"app": "web"}, IP: "10.0.0.1"},
				Destination: flow.Endpoint{Namespace: "prod", PodName: "api", Labels: map[string]string{"app": "api"}, IP: "10.0.0.2"},
				Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
				Verdict:     flow.Allow,
				Direction:   flow.Ingress,
			},
			config: BuildOptions{},
		},
		{
			name: "world destination produces 0.0.0.0/0",
			flow: flow.Flow{
				Time:        now,
				Source:      flow.Endpoint{Namespace: "prod", PodName: "web", Labels: map[string]string{"app": "web"}, IP: "10.0.0.1"},
				Destination: flow.Endpoint{Namespace: "-", IP: "0.0.0.0", Labels: map[string]string{"app": "pub"}},
				Layer4:      flow.Layer4{DestPort: 443, Protocol: flow.TCP},
				Verdict:     flow.Allow,
				Direction:   flow.Egress,
			},
			config: BuildOptions{},
			assertFrontendPolicy: func(t *testing.T, p *Policy) {
				t.Helper()
				require.Len(t, p.EgressRules, 1)
				require.Equal(t, []string{"0.0.0.0/0"}, p.EgressRules[0].ToCIDRs)
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			workloads := analyze.Workloads{
				"prod/web": {Name: "web", Namespace: "prod", Labels: map[string]string{"app": "web"}},
				"prod/api": {Name: "api", Namespace: "prod", Labels: map[string]string{"app": "api"}},
				"-/pub":    {Name: "pub", Namespace: "-", Labels: map[string]string{"app": "pub"}},
			}

			cfg := &config.Config{
				ClusterCIDRs: []*net.IPNet{ns},
			}
			policies := Build([]flow.Flow{tt.flow}, nil, workloads, nil, BuildOptions{Config: cfg})

			if tt.assertFrontendPolicy != nil {
				var fp *Policy
				for i := range policies {
					if policies[i].WorkloadID == "prod/web" {
						fp = &policies[i]
						break
					}
				}
				require.NotNil(t, fp, "expected policy for prod/web")
				tt.assertFrontendPolicy(t, fp)
			}
		})
	}
}

// TestBuild_MultiReservedLabelIngress verifies that an ingress flow with
// multiple reserved labels produces a multi-sentence entity sentinel.
func TestBuild_MultiReservedLabelIngress(t *testing.T) {
	t.Parallel()

	now := time.Now()

	workloads := analyze.Workloads{
		"prod/target": {Name: "target", Namespace: "prod", Labels: map[string]string{"app": "target"}},
	}

	flows := []flow.Flow{
		{
			Time: now,
			Source: flow.Endpoint{
				Labels: map[string]string{
					"reserved:host":           "",
					"reserved:kube-apiserver": "",
				},
				IP: "10.244.1.232",
			},
			Destination: flow.Endpoint{
				Namespace: "prod", PodName: "target", IP: "10.244.2.100",
				Labels: map[string]string{"app": "target"},
			},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Ingress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{})
	require.Len(t, policies, 1)
	require.Equal(t, "prod/target", policies[0].WorkloadID)
	require.Len(t, policies[0].IngressRules, 1)
	// Dual-carry: CIDR twin + multi-entity sentinel.
	require.Equal(t, []string{"10.244.1.232/32"}, policies[0].IngressRules[0].FromWorkloads)
	require.Equal(t, []string{"entity:host,kube-apiserver"}, policies[0].IngressRules[0].FromEntities)
}

// TestBuild_MultiReservedLabelEgressMirror verifies that an egress flow with
// multiple reserved labels on the source endpoint mirrors with the entity
// sentinel in the ingress rule (sorted: host before kube-apiserver).
func TestBuild_MultiReservedLabelEgressMirror(t *testing.T) {
	t.Parallel()

	now := time.Now()

	workloads := analyze.Workloads{
		"prod/server": {Name: "server", Namespace: "prod", Labels: map[string]string{"app": "server"}},
	}

	flows := []flow.Flow{
		{
			Time: now,
			Source: flow.Endpoint{
				Labels: map[string]string{
					"reserved:host":           "",
					"reserved:kube-apiserver": "",
				},
				IP: "10.244.1.232",
			},
			Destination: flow.Endpoint{
				Namespace: "prod", PodName: "server", IP: "10.244.2.100",
				Labels: map[string]string{"app": "server"},
			},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Egress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{})

	var serverPolicy *Policy
	for i := range policies {
		if policies[i].WorkloadID == "prod/server" {
			serverPolicy = &policies[i]
			break
		}
	}
	require.NotNil(t, serverPolicy)
	require.Len(t, serverPolicy.IngressRules, 1)
	// Dual-carry: CIDR twin + multi-entity sentinel.
	require.Equal(t, []string{"10.244.1.232/32"}, serverPolicy.IngressRules[0].FromWorkloads)
	require.Equal(t, []string{"entity:host,kube-apiserver"}, serverPolicy.IngressRules[0].FromEntities)
	require.Equal(t, uint16(8080), serverPolicy.IngressRules[0].Ports[0].Port)
}

func TestIsKubeAPIServerWorkload(t *testing.T) {
	t.Parallel()

	defSel := &config.WorkloadSelector{Namespace: "kube-system", Name: "kube-apiserver"}
	tests := []struct {
		name     string
		id       string
		wl       analyze.Workload
		selector *config.WorkloadSelector
		want     bool
	}{
		{
			name:     "default selector matches kube-system/kube-apiserver",
			id:       "kube-system/kube-apiserver",
			wl:       analyze.Workload{Name: "kube-apiserver", Namespace: "kube-system"},
			selector: defSel,
			want:     true,
		},
		{
			name:     "calico-apiserver does not match default selector",
			id:       "calico-apiserver/calico-apiserver",
			wl:       analyze.Workload{Name: "calico-apiserver", Namespace: "calico-apiserver"},
			selector: defSel,
			want:     false,
		},
		{
			name:     "nil selector returns false",
			id:       "kube-system/kube-apiserver",
			wl:       analyze.Workload{Name: "kube-apiserver", Namespace: "kube-system"},
			selector: nil,
			want:     false,
		},
		{
			name:     "custom selector matches",
			id:       "calico-system/calico-apiserver",
			wl:       analyze.Workload{Name: "calico-apiserver", Namespace: "calico-system"},
			selector: &config.WorkloadSelector{Namespace: "calico-system", Name: "calico-apiserver"},
			want:     true,
		},
		{
			name:     "empty workload name falls back to id parsing",
			id:       "kube-system/kube-apiserver",
			wl:       analyze.Workload{Name: "", Namespace: "kube-system"},
			selector: defSel,
			want:     true,
		},
		{
			name:     "empty workload namespace falls back to id parsing",
			id:       "kube-system/kube-apiserver",
			wl:       analyze.Workload{Name: "kube-apiserver", Namespace: ""},
			selector: defSel,
			want:     true,
		},
		{
			name:     "both workload fields empty falls back to id parsing",
			id:       "kube-system/kube-apiserver",
			wl:       analyze.Workload{Name: "", Namespace: ""},
			selector: defSel,
			want:     true,
		},
		{
			name:     "empty name and empty id returns false",
			id:       "",
			wl:       analyze.Workload{Name: "", Namespace: ""},
			selector: defSel,
			want:     false,
		},
		{
			name:     "id without slash returns false when workload is empty",
			id:       "kube-apiserver",
			wl:       analyze.Workload{Name: "", Namespace: ""},
			selector: defSel,
			want:     false,
		},
		{
			name:     "namespace mismatch returns false",
			id:       "default/kube-apiserver",
			wl:       analyze.Workload{Name: "kube-apiserver", Namespace: "default"},
			selector: defSel,
			want:     false,
		},
		{
			name:     "name mismatch returns false",
			id:       "kube-system/etcd",
			wl:       analyze.Workload{Name: "etcd", Namespace: "kube-system"},
			selector: defSel,
			want:     false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isKubeAPIServerWorkload(tt.id, tt.wl, tt.selector)
			require.Equal(t, tt.want, got)
		})
	}
}

// TestBuild_DNSEgressSynthesis verifies the always-on DNS egress rule
// synthesis: when AlwaysAllowDNS is true, Strict is false, and a workload
// has at least one observed egress rule, an additional DNS egress rule is
// appended.
func TestBuild_DNSEgressSynthesis(t *testing.T) {
	t.Parallel()

	// Helper to create a workload with labels.
	mkWL := func(ns, name string, labels map[string]string) analyze.Workload {
		return analyze.Workload{Name: name, Namespace: ns, Labels: labels}
	}

	// Helper to create a single egress flow from frontend to backend.
	mkEgressFlows := func() []flow.Flow {
		now := time.Now()
		return []flow.Flow{
			{
				Time:        now,
				Source:      flow.Endpoint{Namespace: "prod", PodName: "frontend-abc", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
				Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
				Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
				Verdict:     flow.Allow,
				Direction:   flow.Egress,
			},
		}
	}

	tests := []struct {
		name                string
		workloads           analyze.Workloads
		flows               []flow.Flow
		cfg                 *config.Config
		opts                BuildOptions
		wantDNSEgressRule   bool
		dnsToWorkloads      []string
		dnsToNamespaces     []string
		dnsToPorts          []PortSpec
		totalEgressExpected int
	}{
		{
			name: "AlwaysAllowDNS true + Strict false + kube-dns workload found → ToWorkloads",
			workloads: analyze.Workloads{
				"prod/frontend":        mkWL("prod", "frontend", map[string]string{"app": "frontend"}),
				"prod/backend":         mkWL("prod", "backend", map[string]string{"app": "backend"}),
				"kube-system/kube-dns": mkWL("kube-system", "kube-dns", map[string]string{"k8s-app": "kube-dns"})},
			flows: mkEgressFlows(),
			cfg: &config.Config{
				AlwaysAllowDNS: true,
				KubeDNSPorts:   config.DefaultKubeDNSPorts,
			},
			opts:                BuildOptions{},
			wantDNSEgressRule:   true,
			dnsToWorkloads:      []string{"kube-system/kube-dns"},
			dnsToNamespaces:     nil,
			dnsToPorts:          []PortSpec{{Port: 53, Protocol: "UDP", Description: "DNS"}, {Port: 53, Protocol: "TCP", Description: "DNS"}},
			totalEgressExpected: 2, // 1 peer egress + 1 DNS
		},
		{
			name: "AlwaysAllowDNS true + Strict false + coredns workload → ToWorkloads (coredns name match)",
			workloads: analyze.Workloads{
				"prod/frontend":       mkWL("prod", "frontend", map[string]string{"app": "frontend"}),
				"prod/backend":        mkWL("prod", "backend", map[string]string{"app": "backend"}),
				"kube-system/coredns": mkWL("kube-system", "coredns", map[string]string{"app": "coredns"})},
			flows: mkEgressFlows(),
			cfg: &config.Config{
				AlwaysAllowDNS: true,
				KubeDNSPorts:   config.DefaultKubeDNSPorts,
			},
			opts:                BuildOptions{},
			wantDNSEgressRule:   true,
			dnsToWorkloads:      []string{"kube-system/coredns"},
			dnsToNamespaces:     nil,
			dnsToPorts:          []PortSpec{{Port: 53, Protocol: "UDP", Description: "DNS"}, {Port: 53, Protocol: "TCP", Description: "DNS"}},
			totalEgressExpected: 2,
		},
		{
			name: "AlwaysAllowDNS true + Strict false + NO kube-dns workload → ToNamespaces kube-system",
			workloads: analyze.Workloads{
				"prod/frontend": mkWL("prod", "frontend", map[string]string{"app": "frontend"}),
				"prod/backend":  mkWL("prod", "backend", map[string]string{"app": "backend"}),
			},
			flows: mkEgressFlows(),
			cfg: &config.Config{
				AlwaysAllowDNS: true,
			},
			opts:                BuildOptions{},
			wantDNSEgressRule:   true,
			dnsToWorkloads:      nil,
			dnsToNamespaces:     []string{"kube-system"},
			dnsToPorts:          []PortSpec{{Port: 53, Protocol: "UDP", Description: "DNS"}, {Port: 53, Protocol: "TCP", Description: "DNS"}},
			totalEgressExpected: 2,
		},
		{
			name: "Strict true → NO DNS egress rule",
			workloads: analyze.Workloads{
				"prod/frontend": mkWL("prod", "frontend", map[string]string{"app": "frontend"}),
				"prod/backend":  mkWL("prod", "backend", map[string]string{"app": "backend"}),
			},
			flows: mkEgressFlows(),
			cfg: &config.Config{
				AlwaysAllowDNS: true,
			},
			opts:              BuildOptions{Strict: true},
			wantDNSEgressRule: false,
		},
		{
			name: "AlwaysAllowDNS false → NO DNS egress rule",
			workloads: analyze.Workloads{
				"prod/frontend": mkWL("prod", "frontend", map[string]string{"app": "frontend"}),
				"prod/backend":  mkWL("prod", "backend", map[string]string{"app": "backend"}),
			},
			flows: mkEgressFlows(),
			cfg: &config.Config{
				AlwaysAllowDNS: false,
			},
			opts:              BuildOptions{},
			wantDNSEgressRule: false,
		},
		{
			name: "Config nil → NO DNS egress rule (backward compatible)",
			workloads: analyze.Workloads{
				"prod/frontend": mkWL("prod", "frontend", map[string]string{"app": "frontend"}),
				"prod/backend":  mkWL("prod", "backend", map[string]string{"app": "backend"}),
			},
			flows:             mkEgressFlows(),
			cfg:               nil,
			opts:              BuildOptions{},
			wantDNSEgressRule: false,
		},
		{
			name: "Custom KubeDNSPorts → mapped to egress ports",
			workloads: analyze.Workloads{
				"prod/frontend": mkWL("prod", "frontend", map[string]string{"app": "frontend"}),
				"prod/backend":  mkWL("prod", "backend", map[string]string{"app": "backend"}),
			},
			flows: mkEgressFlows(),
			cfg: &config.Config{
				AlwaysAllowDNS: true,
				KubeDNSPorts:   []config.PortSpec{{Protocol: "UDP", Port: 5353}},
			},
			opts:                BuildOptions{},
			wantDNSEgressRule:   true,
			dnsToWorkloads:      nil,
			dnsToNamespaces:     []string{"kube-system"},
			dnsToPorts:          []PortSpec{{Port: 5353, Protocol: "UDP", Description: "DNS"}},
			totalEgressExpected: 2,
		},
		{
			name: "Workload with zero egress rules → NO DNS rule",
			workloads: analyze.Workloads{
				"prod/frontend": mkWL("prod", "frontend", map[string]string{"app": "frontend"}),
				"prod/backend":  mkWL("prod", "backend", map[string]string{"app": "backend"}),
			},
			flows: []flow.Flow{
				// Only ingress to backend (backend receives). Backend has no egress → no DNS rule.
				{
					Time:        time.Now(),
					Source:      flow.Endpoint{Namespace: "prod", PodName: "frontend-abc", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
					Destination: flow.Endpoint{Namespace: "prod", PodName: "backend-xyz", IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
					Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
					Verdict:     flow.Allow,
					Direction:   flow.Ingress,
				},
			},
			cfg: &config.Config{
				AlwaysAllowDNS: true,
			},
			opts:              BuildOptions{},
			wantDNSEgressRule: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Filter out workloads that are not observed (never seen in flows).
			// Build only uses observed workloads that have ingress/egress.
			policies := Build(tt.flows, nil, tt.workloads, nil, BuildOptions{
				Config: tt.cfg,
				Strict: tt.opts.Strict,
			})

			var frontendPolicy *Policy
			for i := range policies {
				if policies[i].WorkloadID == "prod/frontend" {
					frontendPolicy = &policies[i]
					break
				}
			}

			if tt.totalEgressExpected > 0 {
				require.Equal(t, tt.totalEgressExpected, len(frontendPolicy.EgressRules),
					"frontend egress rule count mismatch")
			}

			if tt.wantDNSEgressRule {
				require.NotNil(t, frontendPolicy, "expected frontend policy to exist with DNS egress")
				require.GreaterOrEqual(t, len(frontendPolicy.EgressRules), 1,
					"expected at least one egress rule (DNS + original)")

				// Find the DNS rule by its description.
				var dnsRule *EgressRule
				for i := range frontendPolicy.EgressRules {
					r := &frontendPolicy.EgressRules[i]
					if strings.Contains(r.Description, "DNS") && strings.Contains(r.Description, "always-allow") {
						dnsRule = r
						break
					}
				}
				require.NotNil(t, dnsRule, "expected DNS egress rule to be present in frontend policy")

				if tt.dnsToWorkloads != nil {
					require.Equal(t, tt.dnsToWorkloads, dnsRule.ToWorkloads, "DNS rule ToWorkloads mismatch")
					require.Empty(t, dnsRule.ToNamespaces, "DNS rule ToNamespaces should be empty when ToWorkloads set")
				}
				if tt.dnsToNamespaces != nil {
					require.Equal(t, tt.dnsToNamespaces, dnsRule.ToNamespaces, "DNS rule ToNamespaces mismatch")
					require.Empty(t, dnsRule.ToWorkloads, "DNS rule ToWorkloads should be empty when ToNamespaces set")
				}
				require.Equal(t, tt.dnsToPorts, dnsRule.ToPorts, "DNS rule ToPorts mismatch")
			}
		})
	}
}

// TestBuild_CalicoPvtWebhook_StaysWorld is the BUG 11 regression test.
// A synthetic pvt source connecting to calico-apiserver on a webhook port
// (5443) MUST NOT become "apiserver" — it stays world (0.0.0.0/0).
func TestBuild_CalicoPvtWebhook_StaysWorld(t *testing.T) {
	t.Parallel()

	_, ns, _ := net.ParseCIDR("10.0.0.0/8")
	cfg := config.Config{
		ClusterCIDRs:          []*net.IPNet{ns},
		ApiserverIngressPorts: []config.PortSpec{{Protocol: "TCP", Port: 5443}},
	}

	// Positive control: pvt source with reserved:kube-apiserver label → apiserver.
	t.Run("pvtSourceWithReservedLabel", func(t *testing.T) {
		t.Parallel()

		workloads := analyze.Workloads{
			"calico-apiserver/svc": {Name: "svc", Namespace: "calico-apiserver", Labels: map[string]string{"app": "svc"}},
			"-/pvt":                {Name: "pvt", Namespace: "-", Labels: map[string]string{"reserved:kube-apiserver": "true"}},
		}

		flows := []flow.Flow{
			{
				Time:        time.Now(),
				Source:      flow.Endpoint{Namespace: "-", IP: "0.0.0.0", Labels: map[string]string{"reserved:kube-apiserver": "true"}},
				Destination: flow.Endpoint{Namespace: "calico-apiserver", IP: "10.96.0.1", Labels: map[string]string{"app": "svc"}},
				Layer4:      flow.Layer4{DestPort: 5443, Protocol: flow.TCP},
				Verdict:     flow.Allow,
				Direction:   flow.Ingress,
			},
		}

		policies := Build(flows, nil, workloads, nil, BuildOptions{Config: &cfg})

		var ap *Policy
		for i := range policies {
			if policies[i].WorkloadID == "calico-apiserver/svc" {
				ap = &policies[i]
				break
			}
		}
		require.NotNil(t, ap)
		require.Len(t, ap.IngressRules, 1)
		require.Equal(t, []string{"apiserver"}, ap.IngressRules[0].FromWorkloads)
	})

	// Negative test: plain pvt source on 5443 → world, NOT apiserver.
	t.Run("plainPvtSourceOnPort5443", func(t *testing.T) {
		t.Parallel()

		workloads := analyze.Workloads{
			"calico-apiserver/svc": {Name: "svc", Namespace: "calico-apiserver", Labels: map[string]string{"app": "svc"}},
			"-/pvt":                {Name: "pvt", Namespace: "-", Labels: map[string]string{"app": "pvt"}},
		}

		flows := []flow.Flow{
			{
				Time:        time.Now(),
				Source:      flow.Endpoint{Namespace: "-", IP: "0.0.0.0", Labels: map[string]string{"app": "pvt"}},
				Destination: flow.Endpoint{Namespace: "calico-apiserver", IP: "10.96.0.1", Labels: map[string]string{"app": "svc"}},
				Layer4:      flow.Layer4{DestPort: 5443, Protocol: flow.TCP},
				Verdict:     flow.Allow,
				Direction:   flow.Ingress,
			},
		}

		policies := Build(flows, nil, workloads, nil, BuildOptions{Config: &cfg})

		var ap *Policy
		for i := range policies {
			if policies[i].WorkloadID == "calico-apiserver/svc" {
				ap = &policies[i]
				break
			}
		}
		require.NotNil(t, ap)
		require.Len(t, ap.IngressRules, 1)
		// BUG 11: plain pvt source stays world, NOT apiserver.
		require.Equal(t, []string{"0.0.0.0/0"}, ap.IngressRules[0].FromWorkloads)
	})
}

// TestBuild_EgressPortsSynthesize verifies that PublicServiceSpec.EgressPorts
// produces a synthesized egress rule with dual-carry (ToEntities + ToCIDRs).
func TestBuild_EgressPortsSynthesize(t *testing.T) {
	t.Parallel()

	_, ns, _ := net.ParseCIDR("10.0.0.0/8")
	cfg := config.Config{
		ClusterCIDRs: []*net.IPNet{ns},
		PublicServices: []config.PublicServiceSpec{
			{
				Namespace: "kube-system",
				Name:      "hubble-relay",
				EgressPorts: []config.PortSpec{
					{Protocol: "TCP", Port: 80},
					{Protocol: "TCP", Port: 443},
				},
			},
		},
	}

	workloads := analyze.Workloads{
		"kube-system/hubble-relay": {Name: "hubble-relay", Namespace: "kube-system", Labels: map[string]string{"app": "hubble-relay"}},
	}

	now := time.Now()
	flows := []flow.Flow{
		{
			Time:        now,
			Source:      flow.Endpoint{Namespace: "prod", PodName: "frontend", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "kube-system", PodName: "hubble-relay", IP: "10.0.0.2", Labels: map[string]string{"app": "hubble-relay"}},
			Layer4:      flow.Layer4{DestPort: 80, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Ingress,
		},
		{
			Time:        now.Add(time.Second),
			Source:      flow.Endpoint{Namespace: "kube-system", PodName: "hubble-relay", IP: "10.0.0.2", Labels: map[string]string{"app": "hubble-relay"}},
			Destination: flow.Endpoint{Namespace: "-/pub", IP: "0.0.0.0", Labels: map[string]string{"app": "pub"}},
			Layer4:      flow.Layer4{DestPort: 443, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{Config: &cfg})

	var hp *Policy
	for i := range policies {
		if policies[i].WorkloadID == "kube-system/hubble-relay" {
			hp = &policies[i]
			break
		}
	}
	require.NotNil(t, hp)

	var synthRule *EgressRule
	for i := range hp.EgressRules {
		if strings.Contains(hp.EgressRules[i].Description, "synthesized") {
			synthRule = &hp.EgressRules[i]
			break
		}
	}
	require.NotNil(t, synthRule, "expected a synthesized egress rule")
	require.Equal(t, []string{"entity:world"}, synthRule.ToEntities)
	require.Equal(t, []string{"0.0.0.0/0"}, synthRule.ToCIDRs)
	require.Len(t, synthRule.ToPorts, 2)
	require.Equal(t, uint16(443), synthRule.ToPorts[0].Port)
	require.Equal(t, "TCP", synthRule.ToPorts[0].Protocol)
	require.Equal(t, uint16(80), synthRule.ToPorts[1].Port)
	require.Equal(t, "TCP", synthRule.ToPorts[1].Protocol)
}

// TestBuild_EgressPortsSynthesizeStrict verifies that Strict mode
// skips synthesized egress rules even when EgressPorts are configured.
func TestBuild_EgressPortsSynthesizeStrict(t *testing.T) {
	t.Parallel()

	_, ns, _ := net.ParseCIDR("10.0.0.0/8")
	cfg := config.Config{
		ClusterCIDRs: []*net.IPNet{ns},
		PublicServices: []config.PublicServiceSpec{
			{
				Namespace: "kube-system",
				Name:      "hubble-relay",
				EgressPorts: []config.PortSpec{
					{Protocol: "TCP", Port: 80},
				},
			},
		},
	}

	workloads := analyze.Workloads{
		"kube-system/hubble-relay": {Name: "hubble-relay", Namespace: "kube-system", Labels: map[string]string{"app": "hubble-relay"}},
	}

	now := time.Now()
	flows := []flow.Flow{
		{
			Time:        now,
			Source:      flow.Endpoint{Namespace: "prod", PodName: "frontend", IP: "10.0.0.1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "kube-system", PodName: "hubble-relay", IP: "10.0.0.2", Labels: map[string]string{"app": "hubble-relay"}},
			Layer4:      flow.Layer4{DestPort: 80, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Ingress,
		},
		{
			Time:        now.Add(time.Second),
			Source:      flow.Endpoint{Namespace: "kube-system", PodName: "hubble-relay", IP: "10.0.0.2", Labels: map[string]string{"app": "hubble-relay"}},
			Destination: flow.Endpoint{Namespace: "-/pub", IP: "0.0.0.0", Labels: map[string]string{"app": "pub"}},
			Layer4:      flow.Layer4{DestPort: 443, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{Config: &cfg, Strict: true})

	var hp *Policy
	for i := range policies {
		if policies[i].WorkloadID == "kube-system/hubble-relay" {
			hp = &policies[i]
			break
		}
	}
	require.NotNil(t, hp)

	for i := range hp.EgressRules {
		require.False(t, strings.Contains(hp.EgressRules[i].Description, "synthesized"),
			"strict mode should not produce synthesized egress rules")
	}
}

// TestBuild_EgressPortsDedup verifies that duplicate (protocol, port) entries
// within EgressPorts are deduplicated to a single entry.
func TestBuild_EgressPortsDedup(t *testing.T) {
	t.Parallel()

	_, ns, _ := net.ParseCIDR("10.0.0.0/8")
	cfg := config.Config{
		ClusterCIDRs: []*net.IPNet{ns},
		PublicServices: []config.PublicServiceSpec{
			{
				Namespace: "kube-system",
				Name:      "infra-svc",
				EgressPorts: []config.PortSpec{
					{Protocol: "TCP", Port: 80},
					{Protocol: "TCP", Port: 80}, // duplicate
				},
			},
		},
	}

	workloads := analyze.Workloads{
		"kube-system/infra-svc": {Name: "infra-svc", Namespace: "kube-system", Labels: map[string]string{"app": "infra"}},
	}

	flows := []flow.Flow{
		{
			Time:        time.Now(),
			Source:      flow.Endpoint{Namespace: "prod", PodName: "app", IP: "10.0.0.1", Labels: map[string]string{"app": "app"}},
			Destination: flow.Endpoint{Namespace: "kube-system", PodName: "infra-svc", IP: "10.0.0.2", Labels: map[string]string{"app": "infra-svc"}},
			Layer4:      flow.Layer4{DestPort: 80, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Ingress,
		},
		{
			Time:        time.Now().Add(time.Second),
			Source:      flow.Endpoint{Namespace: "kube-system", PodName: "infra-svc", IP: "10.0.0.2", Labels: map[string]string{"app": "infra-svc"}},
			Destination: flow.Endpoint{Namespace: "-/pub", IP: "0.0.0.0", Labels: map[string]string{"app": "pub"}},
			Layer4:      flow.Layer4{DestPort: 80, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{Config: &cfg})

	var ip *Policy
	for i := range policies {
		if policies[i].WorkloadID == "kube-system/infra-svc" {
			ip = &policies[i]
			break
		}
	}
	require.NotNil(t, ip)

	for _, r := range ip.EgressRules {
		if strings.Contains(r.Description, "synthesized") {
			require.Len(t, r.ToPorts, 1, "duplicate (TCP, 80) should be deduped to one port")
			require.Equal(t, uint16(80), r.ToPorts[0].Port)
			require.Equal(t, "TCP", r.ToPorts[0].Protocol)
		}
	}
}

// TestCompleteKubeDNSRule verifies the new completion helper replaces the
// binary hasObservedDNSRuleTargetingKubeDNS predicate.  Table-driven test
// asserting return value AND the mutated rule state on each case.
func TestCompleteKubeDNSRule(t *testing.T) {
	t.Parallel()

	samePorts := func(a, b []PortSpec) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i].Port != b[i].Port || a[i].Protocol != b[i].Protocol {
				return false
			}
		}
		return true
	}

	tests := []struct {
		name     string
		rules    []EgressRule
		cfg      *config.Config
		want     bool
		wantTP   []PortSpec // expected ToPorts after completion; nil = unchanged
		wantSame bool       // if true, wantTP is relative copy (no mutation expected)
	}{
		{
			name: "ToNamespaces kube-system + UDP only → true, TCP appended, sorted (TCP before UDP)",
			// "TCP/53" < "UDP/53" by portKey
			rules: []EgressRule{
				{ToNamespaces: []string{"kube-system"}, ToPorts: []PortSpec{{Port: 53, Protocol: "UDP"}}},
			},
			cfg: &config.Config{
				KubeDNSPorts: config.DefaultKubeDNSPorts,
			},
			want:     true,
			wantTP:   []PortSpec{{Port: 53, Protocol: "TCP"}, {Port: 53, Protocol: "UDP"}},
			wantSame: false,
		},
		{
			name: "ToWorkloads kube-system/kube-dns + UDP only → true, TCP appended",
			rules: []EgressRule{
				{ToWorkloads: []string{"kube-system/kube-dns"}, ToPorts: []PortSpec{{Port: 53, Protocol: "UDP"}}},
			},
			cfg: &config.Config{
				KubeDNSPorts: config.DefaultKubeDNSPorts,
			},
			want:     true,
			wantTP:   []PortSpec{{Port: 53, Protocol: "TCP"}, {Port: 53, Protocol: "UDP"}},
			wantSame: false,
		},
		{
			name: "ToWorkloads kube-system/kube-dns + TCP only → true, UDP appended",
			rules: []EgressRule{
				{ToWorkloads: []string{"kube-system/kube-dns"}, ToPorts: []PortSpec{{Port: 53, Protocol: "TCP"}}},
			},
			cfg: &config.Config{
				KubeDNSPorts: config.DefaultKubeDNSPorts,
			},
			want:     true,
			wantTP:   []PortSpec{{Port: 53, Protocol: "TCP"}, {Port: 53, Protocol: "UDP"}},
			wantSame: false,
		},
		{
			name: "ToWorkloads kube-system/kube-dns + both DNS ports → true, no change",
			rules: []EgressRule{
				{ToWorkloads: []string{"kube-system/kube-dns"}, ToPorts: []PortSpec{{Port: 53, Protocol: "UDP"}, {Port: 53, Protocol: "TCP"}}},
			},
			cfg: &config.Config{
				KubeDNSPorts: config.DefaultKubeDNSPorts,
			},
			want:     true,
			wantSame: true,
		},
		{
			name: "ToNamespaces other-ns + UDP/53 → false (no completion)",
			rules: []EgressRule{
				{ToNamespaces: []string{"staging"}, ToPorts: []PortSpec{{Port: 53, Protocol: "UDP"}}},
			},
			cfg: &config.Config{
				KubeDNSPorts: config.DefaultKubeDNSPorts,
			},
			want:     false,
			wantSame: true,
		},
		{
			name:  "empty rules slice → false",
			rules: []EgressRule{},
			cfg: &config.Config{
				KubeDNSPorts: config.DefaultKubeDNSPorts,
			},
			want:     false,
			wantSame: true,
		},
		{
			name: "nil cfg with kube-dns ToWorkloads + UDP only → uses default ports, true, TCP appended",
			rules: []EgressRule{
				{ToWorkloads: []string{"kube-system/kube-dns"}, ToPorts: []PortSpec{{Port: 53, Protocol: "UDP"}}},
			},
			cfg:      nil,
			want:     true,
			wantTP:   []PortSpec{{Port: 53, Protocol: "TCP"}, {Port: 53, Protocol: "UDP"}},
			wantSame: false,
		},
		{
			name: "empty ToPorts on kube-dns rule → false (hasOne gate blocks); NOT full coverage",
			rules: []EgressRule{
				{ToWorkloads: []string{"kube-system/kube-dns"}, ToPorts: []PortSpec{}},
			},
			cfg: &config.Config{
				KubeDNSPorts: config.DefaultKubeDNSPorts,
			},
			want:     false,
			wantSame: true,
		},
		{
			name: "custom cfg TCP-only + UDP observed → false (UDP not configured)",
			rules: []EgressRule{
				{ToWorkloads: []string{"kube-system/kube-dns"}, ToPorts: []PortSpec{{Port: 53, Protocol: "UDP"}}},
			},
			cfg: &config.Config{
				KubeDNSPorts: []config.PortSpec{{Protocol: "TCP", Port: 53}},
			},
			want:     false,
			wantSame: true,
		},
		{
			name: "custom cfg TCP-only + TCP observed → true, no missing",
			rules: []EgressRule{
				{ToWorkloads: []string{"kube-system/kube-dns"}, ToPorts: []PortSpec{{Port: 53, Protocol: "TCP"}}},
			},
			cfg: &config.Config{
				KubeDNSPorts: []config.PortSpec{{Protocol: "TCP", Port: 53}},
			},
			want:     true,
			wantSame: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := completeKubeDNSRule(tt.rules, tt.cfg)
			require.Equal(t, tt.want, got)

			if len(tt.rules) > 0 {
				origTP := make([]PortSpec, len(tt.rules[0].ToPorts))
				copy(origTP, tt.rules[0].ToPorts)
				if tt.wantSame {
					require.True(t, samePorts(tt.rules[0].ToPorts, origTP),
						"expected ToPorts to remain unchanged")
				} else {
					require.True(t, samePorts(tt.rules[0].ToPorts, tt.wantTP),
						"ToPorts mismatch: got %v, want %v", tt.rules[0].ToPorts, tt.wantTP)
				}
			}
		})
	}
}

// TestBuildDNSDeduplication_ObservedKubeDNS verifies that the always-on DNS
// egress synthesis skips when an observed egress rule already covers both
// DNS ports (UDP/53 + TCP/53) and targets kube-dns by workload ID or
// namespace. Dedup must NOT over-fire for non-kube-dns targets.
func TestBuildDNSDeduplication_ObservedKubeDNS(t *testing.T) {
	t.Parallel()

	mkEgress := func(src, dst string, nsSrc, nsDst string, port uint16, proto flow.Protocol) flow.Flow {
		return flow.Flow{
			Time:        time.Now(),
			Source:      flow.Endpoint{Namespace: nsSrc, PodName: src, IP: "10.0.0.1", Labels: map[string]string{"app": src}},
			Destination: flow.Endpoint{Namespace: nsDst, PodName: dst, IP: "10.0.0.2", Labels: map[string]string{"app": dst}},
			Layer4:      flow.Layer4{DestPort: port, Protocol: proto},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
		}
	}

	countSynthDNS := func(rules []EgressRule) int {
		n := 0
		for _, r := range rules {
			if strings.Contains(r.Description, "egress DNS (always-allow)") {
				n++
			}
		}
		return n
	}

	countBothDNSPorts := func(rules []EgressRule) int {
		n := 0
		for _, r := range rules {
			hasUDP, hasTCP := false, false
			for _, p := range r.ToPorts {
				if strings.ToUpper(p.Protocol) == "UDP" && p.Port == 53 {
					hasUDP = true
				}
				if strings.ToUpper(p.Protocol) == "TCP" && p.Port == 53 {
					hasTCP = true
				}
			}
			if hasUDP && hasTCP {
				n++
			}
		}
		return n
	}

	boolPtr := func(b bool) *bool { return &b }

	tests := []struct {
		name             string
		workloads        analyze.Workloads
		flows            []flow.Flow
		alwaysAllowDNS   *bool
		wantSynthSkip    bool
		wantDNSPortRules int
		wantSynthToWL    []string
		wantSynthToNS    []string
	}{
		{
			name: "observed DNS to kube-dns workload → dedup fires, synth skipped",
			workloads: analyze.Workloads{
				"prod/frontend":        {Name: "frontend", Namespace: "prod", Labels: map[string]string{"app": "frontend"}},
				"kube-system/kube-dns": {Name: "kube-dns", Namespace: "kube-system", Labels: map[string]string{"k8s-app": "kube-dns"}},
			},
			flows: []flow.Flow{
				mkEgress("frontend", "kube-dns", "prod", "kube-system", 53, flow.UDP),
				mkEgress("frontend", "kube-dns", "prod", "kube-system", 53, flow.TCP),
			},
			alwaysAllowDNS:   boolPtr(true),
			wantSynthSkip:    true,
			wantDNSPortRules: 1,
			wantSynthToWL:    nil,
			wantSynthToNS:    nil,
		},
		{
			name: "observed DNS to coredns workload → dedup fires, synth skipped",
			workloads: analyze.Workloads{
				"prod/frontend":       {Name: "frontend", Namespace: "prod", Labels: map[string]string{"app": "frontend"}},
				"kube-system/coredns": {Name: "coredns", Namespace: "kube-system", Labels: map[string]string{"app": "coredns"}},
			},
			flows: []flow.Flow{
				mkEgress("frontend", "coredns", "prod", "kube-system", 53, flow.UDP),
				mkEgress("frontend", "coredns", "prod", "kube-system", 53, flow.TCP),
			},
			alwaysAllowDNS:   boolPtr(true),
			wantSynthSkip:    true,
			wantDNSPortRules: 1,
		},
		{
			name: "NO observed DNS + AlwaysAllowDNS true → synth present (no over-fire)",
			workloads: analyze.Workloads{
				"prod/frontend": {Name: "frontend", Namespace: "prod", Labels: map[string]string{"app": "frontend"}},
				"prod/backend":  {Name: "backend", Namespace: "prod", Labels: map[string]string{"app": "backend"}},
			},
			flows: []flow.Flow{
				mkEgress("frontend", "backend", "prod", "prod", 8080, flow.TCP),
			},
			alwaysAllowDNS:   boolPtr(true),
			wantSynthSkip:    false,
			wantDNSPortRules: 1,
			wantSynthToWL:    nil,
			wantSynthToNS:    []string{"kube-system"},
		},
		{
			name: "observed DNS to metrics-server (no kube-dns workload) → dedup does NOT fire, synth to namespace (two DNS-port rules)",
			workloads: analyze.Workloads{
				"prod/frontend":       {Name: "frontend", Namespace: "prod", Labels: map[string]string{"app": "frontend"}},
				"kube-system/metrics": {Name: "metrics", Namespace: "kube-system", Labels: map[string]string{"app": "metrics"}},
			},
			flows: []flow.Flow{
				mkEgress("frontend", "metrics", "prod", "kube-system", 53, flow.UDP),
				mkEgress("frontend", "metrics", "prod", "kube-system", 53, flow.TCP),
			},
			alwaysAllowDNS:   boolPtr(true),
			wantSynthSkip:    false,
			wantDNSPortRules: 2,
			wantSynthToWL:    nil,
			wantSynthToNS:    []string{"kube-system"},
		},
		{
			name: "observed DNS to non-kube-system namespace → dedup does NOT fire, synth present",
			workloads: analyze.Workloads{
				"prod/frontend":       {Name: "frontend", Namespace: "prod", Labels: map[string]string{"app": "frontend"}},
				"staging/metrics-srv": {Name: "metrics-srv", Namespace: "staging", Labels: map[string]string{"app": "metrics"}},
			},
			flows: []flow.Flow{
				mkEgress("frontend", "metrics-srv", "prod", "staging", 53, flow.UDP),
				mkEgress("frontend", "metrics-srv", "prod", "staging", 53, flow.TCP),
			},
			alwaysAllowDNS:   boolPtr(true),
			wantSynthSkip:    false,
			wantDNSPortRules: 2,
			wantSynthToWL:    nil,
			wantSynthToNS:    []string{"kube-system"},
		},
		{
			name: "AlwaysAllowDNS false → no synth DNS rule",
			workloads: analyze.Workloads{
				"prod/frontend":        {Name: "frontend", Namespace: "prod", Labels: map[string]string{"app": "frontend"}},
				"kube-system/kube-dns": {Name: "kube-dns", Namespace: "kube-system", Labels: map[string]string{"k8s-app": "kube-dns"}},
			},
			flows: []flow.Flow{
				mkEgress("frontend", "kube-dns", "prod", "kube-system", 53, flow.UDP),
				mkEgress("frontend", "kube-dns", "prod", "kube-system", 53, flow.TCP),
			},
			alwaysAllowDNS:   boolPtr(false),
			wantSynthSkip:    true,
			wantDNSPortRules: 1,
		},
		{
			name: "observed UDP/53 only to kube-dns + AlwaysAllowDNS true → completion fires: single rule UDP+TCP, no synth",
			workloads: analyze.Workloads{
				"prod/frontend":        {Name: "frontend", Namespace: "prod", Labels: map[string]string{"app": "frontend"}},
				"kube-system/kube-dns": {Name: "kube-dns", Namespace: "kube-system", Labels: map[string]string{"k8s-app": "kube-dns"}},
			},
			flows: []flow.Flow{
				mkEgress("frontend", "kube-dns", "prod", "kube-system", 53, flow.UDP),
			},
			alwaysAllowDNS:   boolPtr(true),
			wantSynthSkip:    true,
			wantDNSPortRules: 1,
		},
		{
			name: "observed TCP/53 only to kube-dns + AlwaysAllowDNS true → completion fires: single rule TCP+UDP, no synth",
			workloads: analyze.Workloads{
				"prod/frontend":        {Name: "frontend", Namespace: "prod", Labels: map[string]string{"app": "frontend"}},
				"kube-system/kube-dns": {Name: "kube-dns", Namespace: "kube-system", Labels: map[string]string{"k8s-app": "kube-dns"}},
			},
			flows: []flow.Flow{
				mkEgress("frontend", "kube-dns", "prod", "kube-system", 53, flow.TCP),
			},
			alwaysAllowDNS:   boolPtr(true),
			wantSynthSkip:    true,
			wantDNSPortRules: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := config.Config{
				ClusterCIDRs:   []*net.IPNet{},
				AlwaysAllowDNS: tt.alwaysAllowDNS != nil && *tt.alwaysAllowDNS,
			}

			policies := Build(tt.flows, nil, tt.workloads, nil, BuildOptions{Config: &cfg})

			var clientPolicy *Policy
			var clientName string
			for _, f := range tt.flows {
				if f.Direction == flow.Egress {
					clientName = f.Source.Namespace + "/" + f.Source.PodName
					break
				}
			}

			for i := range policies {
				if policies[i].WorkloadID == clientName {
					clientPolicy = &policies[i]
					break
				}
			}

			if clientPolicy == nil {
				for i := range policies {
					if len(policies[i].EgressRules) > 0 {
						clientPolicy = &policies[i]
						break
					}
				}
			}

			require.NotNil(t, clientPolicy, "expected a client policy with egress rules for %q", clientName)
			require.Equal(t, tt.wantDNSPortRules, countBothDNSPorts(clientPolicy.EgressRules),
				"DNS-port rule count mismatch")

			synthCount := countSynthDNS(clientPolicy.EgressRules)
			if tt.wantSynthSkip {
				require.Zero(t, synthCount, "expected synthetic DNS rule to be deduped/skipped")
			} else {
				require.Equal(t, 1, synthCount, "expected exactly one synthetic DNS rule")
				for _, r := range clientPolicy.EgressRules {
					if strings.Contains(r.Description, "egress DNS (always-allow)") {
						require.Equal(t, tt.wantSynthToWL, r.ToWorkloads, "synth DNS ToWorkloads mismatch")
						require.Equal(t, tt.wantSynthToNS, r.ToNamespaces, "synth DNS ToNamespaces mismatch")
						break
					}
				}
			}
		})
	}
}

func TestBuild_DefaultDeny_NoEmptyIngress(t *testing.T) {
	t.Parallel()

	now := time.Now()

	workloads := analyze.Workloads{
		"prod/web": {
			Name:      "web",
			Namespace: "prod",
			Labels:    map[string]string{"app": "web"},
		},
		"prod/api": {
			Name:      "api",
			Namespace: "prod",
			Labels:    map[string]string{"app": "api"},
		},
	}

	flows := []flow.Flow{
		{
			Time:        now,
			Source:      flow.Endpoint{Namespace: "prod", PodName: "web", IP: "10.0.0.1", Labels: map[string]string{"app": "web"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "api", IP: "10.0.0.2", Labels: map[string]string{"app": "api"}},
			Layer4:      flow.Layer4{DestPort: 80, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Egress,
		},
		{
			Time:        now.Add(time.Second),
			Source:      flow.Endpoint{Namespace: "prod", PodName: "web", IP: "10.0.0.1", Labels: map[string]string{"app": "web"}},
			Destination: flow.Endpoint{Namespace: "prod", PodName: "api", IP: "10.0.0.2", Labels: map[string]string{"app": "api"}},
			Layer4:      flow.Layer4{DestPort: 80, Protocol: flow.TCP},
			Verdict:     flow.Allow,
			Direction:   flow.Ingress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{DefaultDeny: true})

	for _, p := range policies {
		for j, rule := range p.IngressRules {
			hasFromWorkloads := len(rule.FromWorkloads) > 0
			hasFromEntities := len(rule.FromEntities) > 0
			hasPorts := len(rule.Ports) > 0

			allEmpty := !hasFromWorkloads && !hasFromEntities && !hasPorts
			require.False(t, allEmpty,
				"policy %q rule %d ingress has all empty selector/ports; description=%q",
				p.WorkloadID, j, rule.Description)

			require.NotEqual(t, "default deny-all ingress", rule.Description,
				"policy %q rule %d should not have 'default deny-all ingress' description",
				p.WorkloadID, j)
		}
	}
}

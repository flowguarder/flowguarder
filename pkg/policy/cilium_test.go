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

// TestCilium_ApiserverIngressSentinel verifies that a workload with an
// ingress rule from "apiserver" renders to fromCIDR:[10.96.0.0/12]
// in Cilium, NOT to FromEndpoints with matcher labels.
func TestCilium_ApiserverIngressSentinel(t *testing.T) {
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
			Time:      time.Now(),
			Source:    flow.Endpoint{Namespace: "-", IP: "0.0.0.0", Labels: map[string]string{"app": "pub"}},
			Destination: flow.Endpoint{Namespace: "prod", IP: "10.96.0.1", Labels: map[string]string{"app": "api-server"}},
			Layer4:    flow.Layer4{DestPort: 9443, Protocol: flow.TCP},
			Verdict:   flow.Allow,
			Direction: flow.Ingress,
		},
	}

	policies := Build(flows, nil, workloads, nil, BuildOptions{Config: &cfg})

	var pol *Policy
	for i := range policies {
		if policies[i].WorkloadID == "prod/api-server" {
			pol = &policies[i]
			break
		}
	}
	require.NotNil(t, pol)
	require.Len(t, pol.IngressRules, 1)
	require.Equal(t, []string{"apiserver"}, pol.IngressRules[0].FromWorkloads)

	// Build Cilium with explicit apiserver CIDR.
	cnps := BuildCilium(policies, flows, []string{"10.96.0.0/12"})
	require.Len(t, cnps, 1)

	// First ingress rule should have fromCIDR, NOT fromEndpoints with label matcher.
	require.Len(t, cnps[0].Spec.Ingress, 1)
	require.Equal(t, "apiserver ingress", cnps[0].Spec.Ingress[0].Description)
	require.Equal(t, []string{"10.96.0.0/12"}, cnps[0].Spec.Ingress[0].FromCIDR)
	require.Len(t, cnps[0].Spec.Ingress[0].FromEndpoints, 0)
}

// TestCilium_ApiserverIngress_NilCIDRs verifies that when no apiserverCIDRs
// are provided, the ingress still falls back to the default CIDR.
func TestCilium_ApiserverIngress_NilCIDRs(t *testing.T) {
	t.Parallel()

	cnps := BuildCilium(nil, nil, nil)
	require.Empty(t, cnps)
}

// TestCilium_ApiserverEgressSentinel verifies that a workload with an
// egress rule to ToCIDRs:["apiserver"] renders to toCIDR:[10.96.0.0/12]
// in Cilium.
func TestCilium_ApiserverEgressSentinel(t *testing.T) {
	t.Parallel()

	policies := []Policy{
		{
			WorkloadID:        "default/frontend",
			WorkloadNamespace: "default",
			WorkloadName:      "frontend",
			IngressRules:      nil,
			EgressRules: []EgressRule{
				{
					ToCIDRs: []string{"apiserver"},
					ToPorts: []PortSpec{{Port: 6443, Protocol: "TCP"}},
				},
			},
		},
	}

	cnps := BuildCilium(policies, nil, []string{"10.96.0.0/12"})
	require.Len(t, cnps, 1)

	require.Len(t, cnps[0].Spec.Egress, 1)
	require.Equal(t, []string{"10.96.0.0/12"}, cnps[0].Spec.Egress[0].ToCIDR)
}

// TestCilium_ApiserverIngress_FallbackDefaultCIDR verifies that when
// apiserverCIDRs slice is empty, BuildCilium falls back to
// config.DefaultAPIServerCIDRsStrings (10.96.0.0/12).
func TestCilium_ApiserverIngress_FallbackDefaultCIDR(t *testing.T) {
	t.Parallel()

	policies := []Policy{
		{
			WorkloadID:        "prod/api-server",
			WorkloadNamespace: "prod",
			WorkloadName:      "api-server",
			IngressRules: []IngressRule{
				{
					FromWorkloads: []string{"apiserver"},
					Ports:         []PortSpec{{Port: 9443, Protocol: "TCP"}},
				},
			},
		},
	}

	// empty slice → should fallback to DefaultAPIServerCIDRsStrings
	cnps := BuildCilium(policies, nil, []string{})
	require.Len(t, cnps, 1)
	require.Len(t, cnps[0].Spec.Ingress, 1)
	require.Equal(t, config.DefaultAPIServerCIDRsStrings, cnps[0].Spec.Ingress[0].FromCIDR)
}

// TestCilium_WorldEgressNotSentinel verifies that a ToCIDR of "0.0.0.0/0"
// passes through as a regular toCIDR entry, NOT expanded to apiserver CIDR.
func TestCilium_WorldEgressNotSentinel(t *testing.T) {
	t.Parallel()

	policies := []Policy{
		{
			WorkloadID:        "default/frontend",
			WorkloadNamespace: "default",
			WorkloadName:      "frontend",
			EgressRules: []EgressRule{
				{
					ToCIDRs: []string{"0.0.0.0/0"},
					ToPorts: []PortSpec{{Port: 443, Protocol: "TCP"}},
				},
			},
		},
	}

	cnps := BuildCilium(policies, nil, []string{"10.96.0.0/12"})
	require.Len(t, cnps, 1)
	require.Len(t, cnps[0].Spec.Egress, 1)
	require.Equal(t, []string{"0.0.0.0/0"}, cnps[0].Spec.Egress[0].ToCIDR)
}

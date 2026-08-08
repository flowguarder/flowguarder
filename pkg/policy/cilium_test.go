package policy

import (
	"net"
	"os"
	"strings"
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

	// Case 1: source carries reserved:kube-apiserver label → apiserver override fires.
	t.Run("reservedLabel", func(t *testing.T) {
		t.Parallel()

		cfg := config.Config{
			ClusterCIDRs:          []*net.IPNet{ns},
			ApiserverIngressPorts: []config.PortSpec{{Protocol: "TCP", Port: 9443}},
		}

		workloads := analyze.Workloads{
			"prod/api-server":      {Name: "api-server", Namespace: "prod", Labels: map[string]string{"app": "api-server"}},
			"-/kube-apiserver-res": {Name: "kube-apiserver-res", Namespace: "-", Labels: map[string]string{"reserved:host": "", "reserved:kube-apiserver": ""}},
		}

		flows := []flow.Flow{
			{
				Time:        time.Now(),
				Source:      flow.Endpoint{Namespace: "-", IP: "0.0.0.0", Labels: map[string]string{"reserved:host": "", "reserved:kube-apiserver": ""}},
				Destination: flow.Endpoint{Namespace: "prod", IP: "10.96.0.1", Labels: map[string]string{"app": "api-server"}},
				Layer4:      flow.Layer4{DestPort: 9443, Protocol: flow.TCP},
				Verdict:     flow.Allow,
				Direction:   flow.Ingress,
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

		// Build Cilium.
		cnps := BuildCilium(policies, flows, nil)
		require.Len(t, cnps, 1)

		// apiserver ingress → fromEntities: [kube-apiserver, host, remote-node].
		require.Len(t, cnps[0].Spec.Ingress, 1)
		wantAPI := []string{"host", "kube-apiserver", "remote-node"}
		require.Equal(t, wantAPI, cnps[0].Spec.Ingress[0].FromEntities)
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

		var pol *Policy
		for i := range policies {
			if policies[i].WorkloadID == "prod/api-server" {
				pol = &policies[i]
				break
			}
		}
		require.NotNil(t, pol)
		require.Len(t, pol.IngressRules, 1)
		require.Equal(t, []string{"0.0.0.0/0"}, pol.IngressRules[0].FromWorkloads)
	})
}

// TestCilium_EmptyInput verifies that BuildCilium with nil input returns empty.
func TestCilium_ApiserverIngress_NilCIDRs(t *testing.T) {
	t.Parallel()

	cnps := BuildCilium(nil, nil, nil)
	require.Empty(t, cnps)
}

// TestCilium_BuildCNPFromPolicy_SectionSelector verifies that buildCNPFromPolicy
// derives the endpointSelector from the workload's stable labels, falls back to
// {"app": workloadName} for unknown workloads, and uses stable labels when
// the workload has k8s-app instead of app.
func TestCilium_StableSectionSelector(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                   string
		policy                 Policy
		workloads              analyze.Workloads
		wantEndpointSelector   map[string]string
		wantFromEndpointLabels map[string]string
	}{
		{
			name: "workload with k8s-app instead of app",
			policy: Policy{
				WorkloadID:        "kube-system/kube-dns",
				WorkloadNamespace: "kube-system",
				WorkloadName:      "kube-dns",
			},
			workloads: analyze.Workloads{
				"kube-system/kube-dns": {
					Name:      "kube-dns",
					Namespace: "kube-system",
					Labels:    map[string]string{"k8s-app": "kube-dns"},
				},
			},
			wantEndpointSelector: map[string]string{"k8s-app": "kube-dns"},
		},
		{
			name: "workload with app.kubernetes.io/name stable label",
			policy: Policy{
				WorkloadID:        "default/frontend",
				WorkloadNamespace: "default",
				WorkloadName:      "frontend",
				IngressRules: []IngressRule{
					{
						FromWorkloads: []string{"prod/backend,env=prod"}, // comma-joined cross-namespace format from srcSelectorFor (builder.go)
						Ports:         []PortSpec{{Port: 8080, Protocol: "TCP"}},
					},
				},
			},
			workloads: analyze.Workloads{
				"default/frontend": {
					Name:      "frontend",
					Namespace: "default",
					Labels:    map[string]string{"app.kubernetes.io/name": "frontend"},
				},
				"prod/backend": {
					Name:      "backend",
					Namespace: "prod",
					Labels:    map[string]string{"app.kubernetes.io/name": "backend"},
				},
			},
			wantEndpointSelector: map[string]string{"app.kubernetes.io/name": "frontend"},
			wantFromEndpointLabels: map[string]string{
				"app.kubernetes.io/name":          "backend",
				"env":                             "prod",
				"k8s:io.kubernetes.pod.namespace": "prod",
			},
		},
		{
			name: "unknown workload falls back to app:name",
			policy: Policy{
				WorkloadID:        "prod/orphan-svc",
				WorkloadNamespace: "prod",
				WorkloadName:      "orphan-svc",
				EgressRules: []EgressRule{
					{
						ToWorkloads: []string{"prod/unknown-svc"},
						ToPorts:     []PortSpec{{Port: 443, Protocol: "TCP"}},
					},
				},
			},
			workloads: analyze.Workloads{
				"prod/other-svc": {
					Name:      "other-svc",
					Namespace: "prod",
					Labels:    map[string]string{"app": "other-svc"},
				},
			},
			wantEndpointSelector:   map[string]string{"app": "orphan-svc"},
			wantFromEndpointLabels: map[string]string{"app": "unknown-svc"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			policies := []Policy{tt.policy}
			cnps := BuildCilium(policies, nil, tt.workloads)
			require.Len(t, cnps, 1)

			if tt.wantEndpointSelector != nil {
				require.Equal(t, tt.wantEndpointSelector, cnps[0].Spec.EndpointSelector.MatchLabels)
			} else {
				require.Nil(t, cnps[0].Spec.EndpointSelector.MatchLabels)
			}

			// Check egress-toSelectors if expected.
			if tt.wantFromEndpointLabels != nil {
				if len(cnps[0].Spec.Egress) > 0 {
					require.Len(t, cnps[0].Spec.Egress[0].ToEndpoints, 1)
					require.Equal(t, tt.wantFromEndpointLabels, cnps[0].Spec.Egress[0].ToEndpoints[0].MatchLabels)
				}
				if len(cnps[0].Spec.Ingress) > 0 {
					require.Len(t, cnps[0].Spec.Ingress[0].FromEndpoints, 1)
					require.Equal(t, tt.wantFromEndpointLabels, cnps[0].Spec.Ingress[0].FromEndpoints[0].MatchLabels)
				}
			}
		})
	}
}

// TestCilium_ParseWorkloadSelector_StableLabels tests parseWorkloadSelector
// with the new policyNs parameter for workload-ID branch resolution and
// cross-namespace namespace-key injection.
func TestCilium_ParseWorkloadSelector_StableLabels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		policyNs  string
		workloads analyze.Workloads
		want      map[string]string
	}{
		{
			name:     "same-namespace: known workload stable labels, no namespace key",
			input:    "prod/backend",
			policyNs: "prod",
			workloads: analyze.Workloads{
				"prod/backend": {
					Name:      "backend",
					Namespace: "prod",
					Labels:    map[string]string{"app.kubernetes.io/name": "backend"},
				},
			},
			want: map[string]string{"app.kubernetes.io/name": "backend"},
		},
		{
			name:     "cross-namespace: known workload, inject k8s:io.kubernetes.pod.namespace",
			input:    "prod/backend",
			policyNs: "default",
			workloads: analyze.Workloads{
				"prod/backend": {
					Name:      "backend",
					Namespace: "prod",
					Labels:    map[string]string{"app.kubernetes.io/name": "backend"},
				},
			},
			want: map[string]string{"app.kubernetes.io/name": "backend", "k8s:io.kubernetes.pod.namespace": "prod"},
		},
		{
			name:     "unknown workload falls back to app:name, no namespace key (same ns)",
			input:    "prod/unknown-svc",
			policyNs: "prod",
			workloads: analyze.Workloads{
				"prod/other": {
					Name:      "other",
					Namespace: "prod",
					Labels:    map[string]string{"app": "other"},
				},
			},
			want: map[string]string{"app": "unknown-svc"},
		},
		{
			name:     "unknown workload falls back to app:name, inject namespace key (cross ns)",
			input:    "prod/unknown-svc",
			policyNs: "default",
			workloads: analyze.Workloads{
				"prod/other": {
					Name:      "other",
					Namespace: "prod",
					Labels:    map[string]string{"app": "other"},
				},
			},
			want: map[string]string{"app": "unknown-svc", "k8s:io.kubernetes.pod.namespace": "prod"},
		},
		{
			name:      "known workload with empty labels falls back",
			input:     "staging/zero-label",
			policyNs:  "staging",
			workloads: analyze.Workloads{"staging/zero-label": {Name: "zero-label", Namespace: "staging", Labels: nil}},
			want:      map[string]string{"app": "zero-label"},
		},
		{
			name:      "nil workloads falls back to app:name",
			input:     "prod/backend",
			policyNs:  "prod",
			workloads: nil,
			want:      map[string]string{"app": "backend"},
		},
		{
			name:      "key=value branch unchanged",
			input:     "app.kubernetes.io/name=frontend",
			policyNs:  "default",
			workloads: nil,
			want:      map[string]string{"app.kubernetes.io/name": "frontend"},
		},
		{
			name:      "bare name unchanged",
			input:     "frontend",
			policyNs:  "default",
			workloads: nil,
			want:      map[string]string{"app": "frontend"},
		},
		{
			name:     "cross-namespace comma-joined selector",
			input:    "kube-system/kube-dns,k8s-app=kube-dns",
			policyNs: "flowlab",
			workloads: analyze.Workloads{
				"kube-system/kube-dns": {
					Name:      "kube-dns",
					Namespace: "kube-system",
					Labels:    map[string]string{"k8s-app": "kube-dns"},
				},
			},
			want: map[string]string{"k8s-app": "kube-dns", "k8s:io.kubernetes.pod.namespace": "kube-system"},
		},
		{
			name:     "explicit key=value wins over workload stable label",
			input:    "prod/backend,app=override",
			policyNs: "default",
			workloads: analyze.Workloads{
				"prod/backend": {
					Name:      "backend",
					Namespace: "prod",
					Labels:    map[string]string{"app": "original"},
				},
			},
			want: map[string]string{"app": "override", "k8s:io.kubernetes.pod.namespace": "prod"},
		},
		{
			name:     "explicit k8s:io.kubernetes.pod.namespace not overwritten",
			input:    "prod/backend,k8s:io.kubernetes.pod.namespace=custom",
			policyNs: "default",
			workloads: analyze.Workloads{
				"prod/backend": {
					Name:      "backend",
					Namespace: "prod",
					Labels:    map[string]string{"app": "backend"},
				},
			},
			want: map[string]string{"app": "backend", "k8s:io.kubernetes.pod.namespace": "custom"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			sel := parseWorkloadSelector(tt.input, tt.policyNs, tt.workloads)
			require.NotNil(t, sel)
			require.Equal(t, tt.want, sel.MatchLabels)
		})
	}
}

// TestCilium_ApiserverEgressSentinel verifies that a workload with an
// egress rule to ToCIDRs:["apiserver"] renders to toEntities:[kube-apiserver,host,remote-node]
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

	cnps := BuildCilium(policies, nil, nil)
	require.Len(t, cnps, 1)

	require.Len(t, cnps[0].Spec.Egress, 1)
	wantAPI := []string{"kube-apiserver", "host", "remote-node"}
	require.Equal(t, wantAPI, cnps[0].Spec.Egress[0].ToEntities)
}

// TestCilium_ApiserverIngress_FallbackDefaultCIDR verifies that when
// apiserverCIDRs param is absent, BuildCilium renders apiserver as entities.
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

	// apiserver sentinel → entities regardless of empty/absent CIDRs.
	cnps := BuildCilium(policies, nil, nil)
	require.Len(t, cnps, 1)
	require.Len(t, cnps[0].Spec.Ingress, 1)
	wantAPI := []string{"kube-apiserver", "host", "remote-node"}
	require.Equal(t, wantAPI, cnps[0].Spec.Ingress[0].FromEntities)
}

// TestCilium_WorldEgressEntities verifies that a ToCIDR of "0.0.0.0/0"
// is mapped to Cilium entities (world, cluster, host, remote-node) instead
// of being emitted as toCIDR:0.0.0.0/0 — which would miss in-cluster and host traffic.
func TestCilium_WorldEgressEntities(t *testing.T) {
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

	cnps := BuildCilium(policies, nil, nil)
	require.Len(t, cnps, 1)
	require.Len(t, cnps[0].Spec.Egress, 1)
	wantEntities := []string{"world", "cluster", "host", "remote-node"}
	require.Equal(t, wantEntities, cnps[0].Spec.Egress[0].ToEntities)
	require.Empty(t, cnps[0].Spec.Egress[0].ToCIDR)
}

// TestCilium_IngressCIDR_Guard verifies that a CIDR in FromWorkloads
// renders to FromCIDR (NOT FromEndpoints), confirming the net.ParseCIDR
// guard added in todo 1 still blocks CIDR strings from reaching
// parseWorkloadSelector.
func TestCilium_IngressCIDR_Guard(t *testing.T) {
	t.Parallel()

	policies := []Policy{
		{
			WorkloadID:        "flowlab/demo-server",
			WorkloadNamespace: "flowlab",
			WorkloadName:      "demo-server",
			IngressRules: []IngressRule{
				{
					FromWorkloads: []string{"10.244.0.57/32"},
					Ports:         []PortSpec{{Port: 8080, Protocol: "TCP"}},
				},
			},
		},
	}

	cnps := BuildCilium(policies, nil, nil)
	require.Len(t, cnps, 1)
	require.Len(t, cnps[0].Spec.Ingress, 1)
	require.Equal(t, []string{"10.244.0.57/32"}, cnps[0].Spec.Ingress[0].FromCIDR)
}

// TestCilium_CrossNamespaceSelector verifies that cross-namespace peers
// in ToWorkloads/FromWorkloads receive an explicit
// k8s:io.kubernetes.pod.namespace label in the generated toEndpoints/
// fromEndpoints matchLabels (REVIEW7 BUG 5).
func TestCilium_CrossNamespaceSelector(t *testing.T) {
	t.Parallel()

	// --- Cross-namespace case: ingress to kube-dns (kube-system) from flowlab ---
	crossPolicy := Policy{
		WorkloadID:        "flowlab/demo-client",
		WorkloadNamespace: "flowlab",
		WorkloadName:      "demo-client",
		EgressRules: []EgressRule{
			{
				ToWorkloads: []string{"kube-system/kube-dns"},
				ToPorts:     []PortSpec{{Port: 53, Protocol: "UDP"}},
			},
		},
	}
	workloads := analyze.Workloads{
		"kube-system/kube-dns": {
			Name:      "kube-dns",
			Namespace: "kube-system",
			Labels:    map[string]string{"k8s-app": "kube-dns"},
		},
	}
	cnps := BuildCilium([]Policy{crossPolicy}, nil, workloads)
	require.Len(t, cnps, 1)
	require.Len(t, cnps[0].Spec.Egress, 1)
	require.Len(t, cnps[0].Spec.Egress[0].ToEndpoints, 1)
	require.Equal(t, "kube-system", cnps[0].Spec.Egress[0].ToEndpoints[0].MatchLabels["k8s:io.kubernetes.pod.namespace"])
	// kube-dns stable label preserved alongside namespace key.
	require.Equal(t, "kube-dns", cnps[0].Spec.Egress[0].ToEndpoints[0].MatchLabels["k8s-app"])
}

// TestCilium_WorldPeer_Entities verifies that "world" peers in FromWorkloads
// and ToCIDRs are rendered as Cilium entities (world,cluster,host,remote-node)
// instead of fromCIDR/toCIDR:0.0.0.0/0 (REVIEW7 BUG 6).
func TestCilium_WorldPeer_Entities(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		policy         Policy
		apiserverCIDRs []string // no longer passed to BuildCilium
		wantFromEnt    []string
		wantToEnt      []string
		wantFromCIDR   []string
		wantToCIDR     []string
		wantFromEp     int
		wantToEp       int
	}{
		{
			name: "ingress world via 0.0.0.0/0",
			policy: Policy{
				WorkloadID:        "flowlab/demo-server",
				WorkloadNamespace: "flowlab",
				WorkloadName:      "demo-server",
				IngressRules: []IngressRule{
					{
						FromWorkloads: []string{"0.0.0.0/0"},
						Ports:         []PortSpec{{Port: 53, Protocol: "UDP"}},
					},
				},
			},
			wantFromEnt:  []string{"world", "cluster", "host", "remote-node"},
			wantToEnt:    nil,
			wantFromCIDR: nil,
			wantToCIDR:   nil,
		},
		{
			name: "egress world via 0.0.0.0/0",
			policy: Policy{
				WorkloadID:        "default/demo-client",
				WorkloadNamespace: "default",
				WorkloadName:      "demo-client",
				EgressRules: []EgressRule{
					{
						ToCIDRs: []string{"0.0.0.0/0"},
						ToPorts: []PortSpec{{Port: 443, Protocol: "TCP"}},
					},
				},
			},
			wantFromEnt:  nil,
			wantToEnt:    []string{"world", "cluster", "host", "remote-node"},
			wantFromCIDR: nil,
			wantToCIDR:   nil,
		},
		{
			name: "ingress world via -",
			policy: Policy{
				WorkloadID:        "flowlab/demo-server",
				WorkloadNamespace: "flowlab",
				WorkloadName:      "demo-server",
				IngressRules: []IngressRule{
					{
						FromWorkloads: []string{"-"},
						Ports:         []PortSpec{{Port: 80, Protocol: "TCP"}},
					},
				},
			},
			wantFromEnt:  []string{"world", "cluster", "host", "remote-node"},
			wantToEnt:    nil,
			wantFromCIDR: nil,
			wantToCIDR:   nil,
		},
		{
			name: "ingress world via pub",
			policy: Policy{
				WorkloadID:        "flowlab/demo-server",
				WorkloadNamespace: "flowlab",
				WorkloadName:      "demo-server",
				IngressRules: []IngressRule{
					{
						FromWorkloads: []string{"pub"},
						Ports:         []PortSpec{{Port: 443, Protocol: "TCP"}},
					},
				},
			},
			wantFromEnt:  []string{"world", "cluster", "host", "remote-node"},
			wantToEnt:    nil,
			wantFromCIDR: nil,
			wantToCIDR:   nil,
		},
		{
			name: "specific CIDR stays CIDR ingress",
			policy: Policy{
				WorkloadID:        "flowlab/demo-server",
				WorkloadNamespace: "flowlab",
				WorkloadName:      "demo-server",
				IngressRules: []IngressRule{
					{
						FromWorkloads: []string{"10.244.0.57/32"},
						Ports:         []PortSpec{{Port: 8080, Protocol: "TCP"}},
					},
				},
			},
			wantFromEnt:  nil,
			wantToEnt:    nil,
			wantFromCIDR: []string{"10.244.0.57/32"},
			wantToCIDR:   nil,
		},
		{
			name: "specific CIDR stays CIDR egress",
			policy: Policy{
				WorkloadID:        "default/demo-client",
				WorkloadNamespace: "default",
				WorkloadName:      "demo-client",
				EgressRules: []EgressRule{
					{
						ToCIDRs: []string{"10.244.0.57/32"},
						ToPorts: []PortSpec{{Port: 443, Protocol: "TCP"}},
					},
				},
			},
			wantFromEnt:  nil,
			wantToEnt:    nil,
			wantFromCIDR: nil,
			wantToCIDR:   []string{"10.244.0.57/32"},
		},
		{
			name: "apiserver sentinel renders as entities",
			policy: Policy{
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
			wantFromEnt:  []string{"kube-apiserver", "host", "remote-node"},
			wantToEnt:    nil,
			wantFromCIDR: nil,
			wantToCIDR:   nil,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cnps := BuildCilium([]Policy{tt.policy}, nil, nil)
			require.Len(t, cnps, 1)

			// Ingress checks.
			if len(tt.policy.IngressRules) > 0 {
				require.Len(t, cnps[0].Spec.Ingress, len(tt.policy.IngressRules))
				ing := cnps[0].Spec.Ingress[0]
				require.Equal(t, tt.wantFromEnt, ing.FromEntities)
				require.Equal(t, tt.wantFromCIDR, ing.FromCIDR)
				require.Len(t, ing.FromEndpoints, 0)
			}

			// Egress checks.
			if len(tt.policy.EgressRules) > 0 {
				require.Len(t, cnps[0].Spec.Egress, len(tt.policy.EgressRules))
				egr := cnps[0].Spec.Egress[0]
				require.Equal(t, tt.wantToEnt, egr.ToEntities)
				require.Equal(t, tt.wantToCIDR, egr.ToCIDR)
			}
		})
	}
}

// TestCilium_EntitySentinels verifies that entity sentinels in FromEntities /
// ToEntities are expanded via resolveEntitySet and that CIDR twins are
// suppressed when entities are present (dual-carry guardrail).
func TestCilium_EntitySentinels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		policy Policy
		wantFE []string // FromEntities / ToEntities
		wantFC []string // FromCIDR / ToCIDR
		wantEP int      // expected FromEndpoints count
		wantTE int      // expected ToEndpoints count
	}{
		{
			name: "ingress entity:host",
			policy: Policy{
				WorkloadID:        "prod/api-server",
				WorkloadNamespace: "prod",
				WorkloadName:      "api-server",
				IngressRules: []IngressRule{
					{FromEntities: []string{"entity:host"}, Ports: []PortSpec{{Port: 4222, Protocol: "TCP"}}},
				},
			},
			wantFE: []string{"host", "remote-node"},
			wantFC: nil,
		},
		{
			name: "ingress entity:host,kube-apiserver",
			policy: Policy{
				WorkloadID:        "prod/api-server",
				WorkloadNamespace: "prod",
				WorkloadName:      "api-server",
				IngressRules: []IngressRule{
					{FromEntities: []string{"entity:host,kube-apiserver"}, Ports: []PortSpec{{Port: 8080, Protocol: "TCP"}}},
				},
			},
			wantFE: []string{"host", "kube-apiserver", "remote-node"},
			wantFC: nil,
		},
		{
			name: "ingress entity:kube-apiserver,remote-node",
			policy: Policy{
				WorkloadID:        "prod/api-server",
				WorkloadNamespace: "prod",
				WorkloadName:      "api-server",
				IngressRules: []IngressRule{
					{FromEntities: []string{"entity:kube-apiserver,remote-node"}, Ports: []PortSpec{{Port: 8080, Protocol: "TCP"}}},
				},
			},
			wantFE: []string{"host", "kube-apiserver", "remote-node"},
			wantFC: nil,
		},
		{
			name: "ingress entity:world",
			policy: Policy{
				WorkloadID:        "prod/api-server",
				WorkloadNamespace: "prod",
				WorkloadName:      "api-server",
				IngressRules: []IngressRule{
					{FromEntities: []string{"entity:world"}, Ports: []PortSpec{{Port: 80, Protocol: "TCP"}}},
				},
			},
			wantFE: []string{"cluster", "host", "remote-node", "world"},
			wantFC: nil,
		},
		{
			name: "egress entity:host",
			policy: Policy{
				WorkloadID:        "default/app",
				WorkloadNamespace: "default",
				WorkloadName:      "app",
				EgressRules: []EgressRule{
					{ToEntities: []string{"entity:host"}, ToPorts: []PortSpec{{Port: 4222, Protocol: "TCP"}}},
				},
			},
			wantFE: []string{"host", "remote-node"},
			wantFC: nil,
		},
		{
			name: "egress entity:host,kube-apiserver",
			policy: Policy{
				WorkloadID:        "prod/api-server",
				WorkloadNamespace: "prod",
				WorkloadName:      "api-server",
				EgressRules: []EgressRule{
					{ToEntities: []string{"entity:host,kube-apiserver"}, ToPorts: []PortSpec{{Port: 8080, Protocol: "TCP"}}},
				},
			},
			wantFE: []string{"host", "kube-apiserver", "remote-node"},
			wantFC: nil,
		},
		{
			name: "egress entity:world",
			policy: Policy{
				WorkloadID:        "default/app",
				WorkloadNamespace: "default",
				WorkloadName:      "app",
				EgressRules: []EgressRule{
					{ToEntities: []string{"entity:world"}, ToPorts: []PortSpec{{Port: 443, Protocol: "TCP"}}},
				},
			},
			wantFE: []string{"cluster", "host", "remote-node", "world"},
			wantFC: nil,
		},
		{
			name: "egress entity:host,world",
			policy: Policy{
				WorkloadID:        "default/app",
				WorkloadNamespace: "default",
				WorkloadName:      "app",
				EgressRules: []EgressRule{
					{ToEntities: []string{"entity:host,world"}, ToPorts: []PortSpec{{Port: 443, Protocol: "TCP"}}},
				},
			},
			wantFE: []string{"cluster", "host", "remote-node", "world"},
			wantFC: nil,
		},
		{
			name: "twin-skip ingress: FromWorkloads+FromEntities → FromCIDR empty",
			policy: Policy{
				WorkloadID:        "prod/app",
				WorkloadNamespace: "prod",
				WorkloadName:      "app",
				IngressRules: []IngressRule{
					{
						FromWorkloads: []string{"10.244.0.57/32"},
						FromEntities:  []string{"entity:host,kube-apiserver"},
						Ports:         []PortSpec{{Port: 8080, Protocol: "TCP"}},
					},
				},
			},
			wantFE: []string{"host", "kube-apiserver", "remote-node"},
			wantFC: nil,
		},
		{
			name: "twin-skip egress: ToCIDRs+ToEntities → ToCIDR empty",
			policy: Policy{
				WorkloadID:        "prod/app",
				WorkloadNamespace: "prod",
				WorkloadName:      "app",
				EgressRules: []EgressRule{
					{
						ToCIDRs:    []string{"192.168.107.5/32"},
						ToEntities: []string{"entity:kube-apiserver,remote-node"},
						ToPorts:    []PortSpec{{Port: 443, Protocol: "TCP"}},
					},
				},
			},
			wantFE: []string{"host", "kube-apiserver", "remote-node"},
			wantFC: nil,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cnps := BuildCilium([]Policy{tt.policy}, nil, nil)
			require.Len(t, cnps, 1)

			// Ingress assertions.
			if len(tt.policy.IngressRules) > 0 {
				require.Len(t, cnps[0].Spec.Ingress, len(tt.policy.IngressRules))
				ing := cnps[0].Spec.Ingress[0]
				require.Equal(t, tt.wantFE, ing.FromEntities, "FromEntities mismatch")
				require.Equal(t, tt.wantFC, ing.FromCIDR, "FromCIDR mismatch")
				require.Len(t, ing.FromEndpoints, tt.wantEP)
			}

			// Egress assertions.
			if len(tt.policy.EgressRules) > 0 {
				require.Len(t, cnps[0].Spec.Egress, len(tt.policy.EgressRules))
				egr := cnps[0].Spec.Egress[0]
				require.Equal(t, tt.wantFE, egr.ToEntities, "ToEntities mismatch")
				require.Equal(t, tt.wantFC, egr.ToCIDR, "ToCIDR mismatch")
				require.Len(t, egr.ToEndpoints, tt.wantTE)
			}
		})
	}
}

// TestCilium_PortProtocol verifies port protocol normalization (BUG 7).
func TestCilium_PortProtocol(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		policy           Policy
		wantIngressProto string
		wantEgressProto  string
	}{
		{
			name: "ingress TCP",
			policy: Policy{
				WorkloadID:        "flowlab/demo-server",
				WorkloadNamespace: "flowlab",
				WorkloadName:      "demo-server",
				IngressRules: []IngressRule{
					{FromWorkloads: []string{"flowlab/demo-client"}, Ports: []PortSpec{{Port: 80, Protocol: "TCP"}}},
				},
			},
			wantIngressProto: "TCP",
		},
		{
			name: "egress UDP",
			policy: Policy{
				WorkloadID:        "flowlab/demo-client",
				WorkloadNamespace: "flowlab",
				WorkloadName:      "demo-client",
				EgressRules: []EgressRule{
					{ToWorkloads: []string{"kube-system/kube-dns"}, ToPorts: []PortSpec{{Port: 53, Protocol: "UDP"}}},
				},
			},
			wantEgressProto: "UDP",
		},
		{
			name: "empty protocol normalizes to ANY",
			policy: Policy{
				WorkloadID:        "flowlab/demo-server",
				WorkloadNamespace: "flowlab",
				WorkloadName:      "demo-server",
				IngressRules: []IngressRule{
					{FromWorkloads: []string{"flowlab/demo-client"}, Ports: []PortSpec{{Port: 443, Protocol: ""}}},
				},
			},
			wantIngressProto: "ANY",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cnps := BuildCilium([]Policy{tt.policy}, nil, nil)
			require.Len(t, cnps, 1)

			if tt.wantIngressProto != "" {
				require.Len(t, cnps[0].Spec.Ingress, 1)
				require.Len(t, cnps[0].Spec.Ingress[0].ToPorts, 1)
				ports := cnps[0].Spec.Ingress[0].ToPorts[0].Ports
				require.Len(t, ports, 1)
				require.Equal(t, tt.wantIngressProto, ports[0].Protocol)
				if tt.wantIngressProto != "ANY" {
					for _, p := range ports {
						require.NotEqual(t, "ANY", p.Protocol, "unexpected ANY in concrete-protocol port")
					}
				}
			}

			if tt.wantEgressProto != "" {
				require.Len(t, cnps[0].Spec.Egress, 1)
				require.Len(t, cnps[0].Spec.Egress[0].ToPorts, 1)
				ports := cnps[0].Spec.Egress[0].ToPorts[0].Ports
				require.Len(t, ports, 1)
				require.Equal(t, tt.wantEgressProto, ports[0].Protocol)
				if tt.wantEgressProto != "ANY" {
					for _, p := range ports {
						require.NotEqual(t, "ANY", p.Protocol, "unexpected ANY in concrete-protocol port")
					}
				}
			}
		})
	}
}

// TestCilium_DNSDeduplication verifies at most one DNS rule per CNPToPorts block (BUG 8).
func TestCilium_DNSDeduplication(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		policy            Policy
		wantDNSBlocks     int
		egressPort53Ports int
	}{
		{
			name: "ingress TCP+UDP port 53 is L4-only",
			policy: Policy{
				WorkloadID:        "kube-system/kube-dns",
				WorkloadNamespace: "kube-system",
				WorkloadName:      "kube-dns",
				IngressRules: []IngressRule{
					{FromWorkloads: []string{"flowlab/demo-client"}, Ports: []PortSpec{{Port: 53, Protocol: "UDP"}, {Port: 53, Protocol: "TCP"}}},
				},
			},
			wantDNSBlocks:     0,
			egressPort53Ports: 0,
		},
		{
			name: "egress port 53 DNS",
			policy: Policy{
				WorkloadID:        "flowlab/demo-client",
				WorkloadNamespace: "flowlab",
				WorkloadName:      "demo-client",
				EgressRules: []EgressRule{
					{ToWorkloads: []string{"kube-system/kube-dns"}, ToPorts: []PortSpec{{Port: 53, Protocol: "UDP"}}},
				},
			},
			egressPort53Ports: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cnps := BuildCilium([]Policy{tt.policy}, nil, nil)
			require.Len(t, cnps, 1)

			dnsBlockCount := 0

			for i := range cnps[0].Spec.Ingress {
				ing := cnps[0].Spec.Ingress[i]
				for _, tp := range ing.ToPorts {
					if tp.Rules == nil {
						continue
					}
					if len(tp.Rules.DNS) == 0 {
						continue
					}
					dnsBlockCount++
					require.Len(t, tp.Rules.DNS, 1, "block must have exactly 1 DNS rule, got %d", len(tp.Rules.DNS))
					require.Equal(t, "*", tp.Rules.DNS[0].MatchPattern)
				}
			}
			if tt.wantDNSBlocks > 0 {
				require.Equal(t, tt.wantDNSBlocks, dnsBlockCount, "expected %d DNS blocks in ingress", tt.wantDNSBlocks)
			}

			for i := range cnps[0].Spec.Egress {
				egr := cnps[0].Spec.Egress[i]
				for _, tp := range egr.ToPorts {
					if tp.Rules == nil {
						continue
					}
					if len(tp.Rules.DNS) == 0 {
						continue
					}
					if tp.Ports != nil && tp.Ports[0].Port == "53" {
						require.Len(t, tp.Rules.DNS, 1, "egress port-53 block must have exactly 1 DNS rule, got %d", len(tp.Rules.DNS))
					}
				}
			}
			if tt.egressPort53Ports > 0 {
				dnsEgressCount := 0
				for i := range cnps[0].Spec.Egress {
					for _, tp := range cnps[0].Spec.Egress[i].ToPorts {
						if tp.Rules != nil && len(tp.Rules.DNS) > 0 && tp.Ports != nil && tp.Ports[0].Port == "53" {
							dnsEgressCount++
						}
					}
				}
				require.Equal(t, tt.egressPort53Ports, dnsEgressCount, "expected %d DNS egress port-53 blocks", tt.egressPort53Ports)
			}
		})
	}
}

func TestCilium_Port53L4Only(t *testing.T) {
	t.Parallel()

	t.Run("ingress port 53 UDP+TCP has no Rules-DNS", func(t *testing.T) {
		t.Parallel()

		cnps := BuildCilium([]Policy{{
			WorkloadID:        "kube-system/kube-dns",
			WorkloadNamespace: "kube-system",
			WorkloadName:      "kube-dns",
			IngressRules: []IngressRule{
				{
					FromWorkloads: []string{"flowlab/demo-client"},
					Ports:         []PortSpec{{Port: 53, Protocol: "UDP"}, {Port: 53, Protocol: "TCP"}},
				},
			},
		}}, nil, nil)
		require.Len(t, cnps, 1)
		require.Len(t, cnps[0].Spec.Ingress, 1)

		for _, tp := range cnps[0].Spec.Ingress[0].ToPorts {
			require.Len(t, tp.Ports, 1, "expected exactly 1 port entry")
			require.Equal(t, "53", tp.Ports[0].Port)
			if tp.Rules != nil {
				require.Empty(t, tp.Rules.DNS, "ingress port-53 block must NOT have Rules.DNS (pure L4)")
			}
		}
	})

	t.Run("egress port 53 has DNS L7 rule", func(t *testing.T) {
		t.Parallel()

		cnps := BuildCilium([]Policy{{
			WorkloadID:        "flowlab/demo-client",
			WorkloadNamespace: "flowlab",
			WorkloadName:      "demo-client",
			EgressRules: []EgressRule{
				{
					ToWorkloads: []string{"kube-system/kube-dns"},
					ToPorts:     []PortSpec{{Port: 53, Protocol: "UDP"}},
				},
			},
		}}, nil, nil)
		require.Len(t, cnps, 1)
		require.Len(t, cnps[0].Spec.Egress, 1)

		// Find the port-53 ToPorts block and assert DNS L7 presence.
		var found bool
		for _, tp := range cnps[0].Spec.Egress[0].ToPorts {
			if tp.Ports != nil && tp.Ports[0].Port == "53" {
				found = true
				require.NotNil(t, tp.Rules, "egress port-53 block must have Rules")
				require.Len(t, tp.Rules.DNS, 1, "egress port-53 block must have exactly 1 DNS rule")
				require.Equal(t, "*", tp.Rules.DNS[0].MatchPattern)
			}
		}
		require.True(t, found, "expected a port-53 ToPorts block in egress")
	})
}

// TestCilium_ToNamespaces verifies that EgressRule.ToNamespaces renders as
// ToEndpoints peers keyed by namespace (REVIEW10 todo 4).
func TestCilium_ToNamespaces(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		policy      Policy
		wantTECount int
		wantTENs    []string // expected namespace values in ToEndpoints (slice order)
	}{
		{
			name: "DNS fallback: single namespace with ports",
			policy: Policy{
				WorkloadID:        "flowlab/demo-client",
				WorkloadNamespace: "flowlab",
				WorkloadName:      "demo-client",
				EgressRules: []EgressRule{
					{
						ToNamespaces: []string{"kube-system"},
						ToPorts:      []PortSpec{{Port: 53, Protocol: "UDP"}, {Port: 53, Protocol: "TCP"}},
					},
				},
			},
			wantTECount: 1,
			wantTENs:    []string{"kube-system"},
		},
		{
			name: "multiple namespaces",
			policy: Policy{
				WorkloadID:        "flowlab/svc",
				WorkloadNamespace: "flowlab",
				WorkloadName:      "svc",
				EgressRules: []EgressRule{
					{
						ToNamespaces: []string{"kube-system", "monitoring"},
						ToPorts:      []PortSpec{{Port: 443, Protocol: "TCP"}},
					},
				},
			},
			wantTECount: 2,
			wantTENs:    []string{"kube-system", "monitoring"},
		},
		{
			name: "ToNamespaces combined with ToWorkloads",
			policy: Policy{
				WorkloadID:        "flowlab/svc",
				WorkloadNamespace: "flowlab",
				WorkloadName:      "svc",
				EgressRules: []EgressRule{
					{
						ToWorkloads:  []string{"flowlab/backend"},
						ToNamespaces: []string{"kube-system"},
						ToPorts:      []PortSpec{{Port: 443, Protocol: "TCP"}},
					},
				},
			},
			wantTECount: 2, // 1 ToWorkloads + 1 ToNamespaces
			wantTENs:    []string{"kube-system"},
		},
		{
			name: "empty ToNamespaces produces no extra namespace peer",
			policy: Policy{
				WorkloadID:        "flowlab/svc",
				WorkloadNamespace: "flowlab",
				WorkloadName:      "svc",
				EgressRules: []EgressRule{
					{
						ToWorkloads:  []string{"flowlab/backend"},
						ToNamespaces: []string{},
						ToPorts:      []PortSpec{{Port: 8080, Protocol: "TCP"}},
					},
				},
			},
			wantTECount: 1,
			wantTENs:    nil,
		},
		{
			name: "nil ToNamespaces produces no extra namespace peer",
			policy: Policy{
				WorkloadID:        "flowlab/svc",
				WorkloadNamespace: "flowlab",
				WorkloadName:      "svc",
				EgressRules: []EgressRule{
					{
						ToWorkloads: []string{"flowlab/backend"},
						ToPorts:     []PortSpec{{Port: 8080, Protocol: "TCP"}},
					},
				},
			},
			wantTECount: 1,
			wantTENs:    nil,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cnps := BuildCilium([]Policy{tt.policy}, nil, nil)
			require.Len(t, cnps, 1)
			require.Len(t, cnps[0].Spec.Egress, 1)

			egr := cnps[0].Spec.Egress[0]
			require.Len(t, egr.ToEndpoints, tt.wantTECount)

			// Verify namespace peer values when expected.
			nsCount := 0
			for _, ep := range egr.ToEndpoints {
				if v, ok := ep.MatchLabels["k8s:io.kubernetes.pod.namespace"]; ok {
					require.Contains(t, tt.wantTENs, v, "unexpected namespace peer label value")
					nsCount++
				}
			}
			require.Equal(t, len(tt.wantTENs), nsCount, "did not find expected number of namespace peers")

			// Ports must still be present on the rule.
			require.GreaterOrEqual(t, len(egr.ToPorts), 1, "toPorts must be non-empty")
		})
	}
}

// TestCilium_Filename verifies CNP filename generation uses ns-name.yaml format
// and Metadata.Name does NOT have a "policy-" prefix.
func TestCilium_Filename(t *testing.T) {
	t.Parallel()

	workloads := analyze.Workloads{
		"kube-system/kube-dns": {
			Name: "kube-dns", Namespace: "kube-system",
			Labels: map[string]string{"k8s-app": "kube-dns"},
		},
		"flowlab/demo-client": {
			Name: "demo-client", Namespace: "flowlab",
			Labels: map[string]string{"app": "demo-client"},
		},
	}

	policies := []Policy{
		{
			WorkloadID:        "kube-system/kube-dns",
			WorkloadNamespace: "kube-system",
			WorkloadName:      "kube-dns",
			IngressRules: []IngressRule{
				{FromWorkloads: []string{"flowlab/demo-client"}, Ports: []PortSpec{{Port: 53, Protocol: "UDP"}}},
			},
		},
		{
			WorkloadID:        "flowlab/demo-client",
			WorkloadNamespace: "flowlab",
			WorkloadName:      "demo-client",
			EgressRules: []EgressRule{
				{ToWorkloads: []string{"kube-system/kube-dns"}, ToPorts: []PortSpec{{Port: 53, Protocol: "UDP"}}},
			},
		},
	}

	dir := t.TempDir()
	cnps := BuildCilium(policies, nil, workloads)
	require.Len(t, cnps, 2)

	for _, cnp := range cnps {
		require.False(t, strings.HasPrefix(cnp.Metadata.Name, "policy-"),
			"Metadata.Name %q must not start with policy-", cnp.Metadata.Name)
	}

	err := WriteCiliumYAML(cnps, dir)
	require.NoError(t, err)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	expectedFilenames := map[string]bool{
		"flowlab-demo-client.yaml":  true,
		"kube-system-kube-dns.yaml": true,
	}

	foundNames := make(map[string]bool)
	for _, e := range entries {
		foundNames[e.Name()] = true
		require.False(t, strings.HasPrefix(e.Name(), "policy-policy"),
			"filename must not double-prefix: got %s", e.Name())
		require.False(t, strings.HasPrefix(e.Name(), "policy-"),
			"filename must not start with policy-: got %s", e.Name())
	}
	for fn := range expectedFilenames {
		require.True(t, foundNames[fn], "expected file %s was not found", fn)
	}
}

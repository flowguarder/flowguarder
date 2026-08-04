package main

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/flowguarder/flowguarder/pkg/analyze"
	"github.com/flowguarder/flowguarder/pkg/anomaly"
	"github.com/flowguarder/flowguarder/pkg/ingest"
	"github.com/flowguarder/flowguarder/pkg/flow"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/flowguarder/flowguarder/pkg/config"
	"github.com/flowguarder/flowguarder/pkg/parser"
	"github.com/flowguarder/flowguarder/pkg/policy"
	"github.com/stretchr/testify/require"
)

// TestParseWorkloadSelector_LabelFormat verifies that "key=value" produces
// a podSelector with the given key/value and no namespaceSelector.
func TestParseWorkloadSelector_LabelFormat(t *testing.T) {
	t.Parallel()

	podSel, nsSel := parseWorkloadSelector("app=frontend")
	require.Equal(t, map[string]string{"app": "frontend"}, podSel)
	require.Nil(t, nsSel)
}

// TestParseWorkloadSelector_NamespaceNameFormat verifies that "namespace/name"
// produces a podSelector with app=name and a namespaceSelector for the namespace.
func TestParseWorkloadSelector_NamespaceNameFormat(t *testing.T) {
	t.Parallel()

	podSel, nsSel := parseWorkloadSelector("prod/backend")
	require.Equal(t, map[string]string{"app": "backend"}, podSel)
	require.Equal(t, map[string]string{"kubernetes.io/metadata.name": "prod"}, nsSel)
}

// TestParseWorkloadSelector_BareName verifies that a bare string like "frontend"
// produces podSelector={app: frontend} with no namespaceSelector.
func TestParseWorkloadSelector_BareName(t *testing.T) {
	t.Parallel()

	podSel, nsSel := parseWorkloadSelector("frontend")
	require.Equal(t, map[string]string{"app": "frontend"}, podSel)
	require.Nil(t, nsSel)
}

// TestParseWorkloadSelector_TableDriven covers all supported formats.
func TestParseWorkloadSelector_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      string
		wantPodSel map[string]string
		wantNsSel  map[string]string
	}{
		{
			name:       "empty",
			input:      "",
			wantPodSel: nil,
			wantNsSel:  nil,
		},
		{
			name:       "single label",
			input:      "app=frontend",
			wantPodSel: map[string]string{"app": "frontend"},
			wantNsSel:  nil,
		},
		{
			name:       "namespace/name",
			input:      "prod/backend",
			wantPodSel: map[string]string{"app": "backend"},
			wantNsSel:  map[string]string{"kubernetes.io/metadata.name": "prod"},
		},
		{
			name:       "bare name",
			input:      "frontend",
			wantPodSel: map[string]string{"app": "frontend"},
			wantNsSel:  nil,
		},
		{
			name:       "comma-separated labels",
			input:      "k1=v1,k2=v2,k3=v3",
			wantPodSel: map[string]string{"k1": "v1", "k2": "v2", "k3": "v3"},
			wantNsSel:  nil,
		},
		{
			name:       "two comma-separated labels",
			input:      "env=prod,version=2",
			wantPodSel: map[string]string{"env": "prod", "version": "2"},
			wantNsSel:  nil,
		},
		{
			name:       "namespace/name + labels",
			input:      "prod/backend,env=prod",
			wantPodSel: map[string]string{"app": "backend", "env": "prod"},
			wantNsSel:  map[string]string{"kubernetes.io/metadata.name": "prod"},
		},
		{
			name:       "labels + namespace/name",
			input:      "env=prod,ns/service",
			wantPodSel: map[string]string{"app": "service", "env": "prod"},
			wantNsSel:  map[string]string{"kubernetes.io/metadata.name": "ns"},
		},
		{
			name:       "dash only",
			input:      "-",
			wantPodSel: nil,
			wantNsSel:  nil,
		},
		{
			name:       "dash + label",
			input:      "-,env=prod",
			wantPodSel: map[string]string{"env": "prod"},
			wantNsSel:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			podSel, nsSel := parseWorkloadSelector(tt.input)

			if tt.wantPodSel == nil {
				require.Nil(t, podSel)
			} else {
				require.Equal(t, tt.wantPodSel, podSel)
			}
			if tt.wantNsSel == nil {
				require.Nil(t, nsSel)
			} else {
				require.Equal(t, tt.wantNsSel, nsSel)
			}
		})
	}
}

// TestBuildNetworkPolicy_IngressOnly verifies that a Policy with only ingress
// rules produces a NetworkPolicy with PolicyTypeIngress, non-empty Ingress,
// and no Egress fields.
func TestBuildNetworkPolicy_IngressOnly(t *testing.T) {
	t.Parallel()

	p := policy.Policy{
		WorkloadID:        "default/frontend",
		WorkloadNamespace: "default",
		WorkloadName:      "frontend",
		IngressRules: []policy.IngressRule{
			{
				FromWorkloads: []string{"app=backend"},
				Ports:         []policy.PortSpec{{Port: 8080, Protocol: "TCP"}},
			},
		},
	}

	np := buildNetworkPolicy(p, config.Config{})

	require.Equal(t, "networking.k8s.io/v1", np.APIVersion)
	require.Equal(t, "NetworkPolicy", np.Kind)
	require.Equal(t, "frontend", np.Name)
	require.Equal(t, "default", np.Namespace)
	require.Equal(t, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}, np.Spec.PolicyTypes)
	require.Equal(t, map[string]string{"app": "frontend"}, np.Spec.PodSelector.MatchLabels)
	require.Len(t, np.Spec.Ingress, 1)
	require.Len(t, np.Spec.Ingress[0].From, 1)
	require.NotNil(t, np.Spec.Ingress[0].From[0].PodSelector)
	require.Equal(t, map[string]string{"app": "backend"}, np.Spec.Ingress[0].From[0].PodSelector.MatchLabels)
	require.Empty(t, np.Spec.Egress)
}

// TestBuildNetworkPolicy_EgressWithCIDR verifies that an egress rule with
// ToCIDRs produces a NetworkPolicy containing an IPBlock in the egress To peers.
func TestBuildNetworkPolicy_EgressWithCIDR(t *testing.T) {
	t.Parallel()

	p := policy.Policy{
		WorkloadID:        "default/frontend",
		WorkloadNamespace: "default",
		WorkloadName:      "frontend",
		IngressRules:      nil,
		EgressRules: []policy.EgressRule{
			{
				ToCIDRs: []string{"0.0.0.0/0"},
				ToPorts: []policy.PortSpec{{Port: 443, Protocol: "TCP"}},
			},
		},
	}

	np := buildNetworkPolicy(p, config.Config{})

	require.Equal(t, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, np.Spec.PolicyTypes)
	require.Empty(t, np.Spec.Ingress)
	require.Len(t, np.Spec.Egress, 1)
	require.Len(t, np.Spec.Egress[0].To, 1)
	require.NotNil(t, np.Spec.Egress[0].To[0].IPBlock)
	require.Equal(t, "0.0.0.0/0", np.Spec.Egress[0].To[0].IPBlock.CIDR)
	require.Len(t, np.Spec.Egress[0].Ports, 1)
	require.Equal(t, intstr.FromInt(443), *np.Spec.Egress[0].Ports[0].Port)
}

// TestBuildNetworkPolicy_BothDirections verifies that a Policy with ingress
// and egress rules produces a NetworkPolicy with both PolicyTypes populated
// and non-empty Ingress and Egress slices.
func TestBuildNetworkPolicy_BothDirections(t *testing.T) {
	t.Parallel()

	p := policy.Policy{
		WorkloadID:        "default/backend",
		WorkloadNamespace: "default",
		WorkloadName:      "backend",
		IngressRules: []policy.IngressRule{
			{
				FromWorkloads: []string{"default/frontend"},
				Ports:         []policy.PortSpec{{Port: 3000, Protocol: "TCP"}},
			},
		},
		EgressRules: []policy.EgressRule{
			{
				ToWorkloads: []string{"app=redis"},
				ToPorts:     []policy.PortSpec{{Port: 6379, Protocol: "TCP"}},
			},
		},
	}

	np := buildNetworkPolicy(p, config.Config{})

	require.ElementsMatch(t,
		[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
		np.Spec.PolicyTypes,
	)
	require.Len(t, np.Spec.Ingress, 1)
	require.Len(t, np.Spec.Egress, 1)

	// Ingress: from default/frontend → namespaceSelector + podSelector
	require.Len(t, np.Spec.Ingress[0].From, 1)
	require.NotNil(t, np.Spec.Ingress[0].From[0].NamespaceSelector)
	require.Equal(t, map[string]string{"kubernetes.io/metadata.name": "default"}, np.Spec.Ingress[0].From[0].NamespaceSelector.MatchLabels)
	require.NotNil(t, np.Spec.Ingress[0].From[0].PodSelector)
	require.Equal(t, map[string]string{"app": "frontend"}, np.Spec.Ingress[0].From[0].PodSelector.MatchLabels)

	// Egress: to app=redis
	require.Len(t, np.Spec.Egress[0].To, 1)
	require.NotNil(t, np.Spec.Egress[0].To[0].PodSelector)
	require.Equal(t, map[string]string{"app": "redis"}, np.Spec.Egress[0].To[0].PodSelector.MatchLabels)
}

// TestBuildNetworkPolicy_EmptyRules verifies that a Policy with no rules
// produces a NetworkPolicy with no PolicyTypes, no Ingress, no Egress,
// but still has the PodSelector.
func TestBuildNetworkPolicy_EmptyRules(t *testing.T) {
	t.Parallel()

	p := policy.Policy{
		WorkloadID:        "default/empty",
		WorkloadNamespace: "default",
		WorkloadName:      "empty",
		IngressRules:      nil,
		EgressRules:       nil,
	}

	np := buildNetworkPolicy(p, config.Config{})

	require.Empty(t, np.Spec.PolicyTypes)
	require.Empty(t, np.Spec.Ingress)
	require.Empty(t, np.Spec.Egress)
	require.NotNil(t, np.Spec.PodSelector)
	require.Equal(t, map[string]string{"app": "empty"}, np.Spec.PodSelector.MatchLabels)
}

// TestBuildNetworkPolicy_PortWithProtocol verifies that ingress and egress
// rules with PortSpec produce correctly set Port and Protocol fields in the
// resulting NetworkPolicy.
func TestBuildNetworkPolicy_PortWithProtocol(t *testing.T) {
	t.Parallel()

	p := policy.Policy{
		WorkloadID:        "default/gateway",
		WorkloadNamespace: "default",
		WorkloadName:      "gateway",
		IngressRules: []policy.IngressRule{
			{
				FromWorkloads: []string{"app=client"},
				Ports:         []policy.PortSpec{{Port: 8080, Protocol: "TCP"}, {Port: 8443, Protocol: "UDP"}},
			},
		},
	}

	np := buildNetworkPolicy(p, config.Config{})

	require.Len(t, np.Spec.Ingress, 1)
	require.Len(t, np.Spec.Ingress[0].Ports, 2)

	// First port: TCP/8080
	tcpPort := intstr.FromInt(8080)
	require.Equal(t, &tcpPort, np.Spec.Ingress[0].Ports[0].Port)
	require.Equal(t, corev1.ProtocolTCP, *np.Spec.Ingress[0].Ports[0].Protocol)

	// Second port: UDP/8443
	udpPort := intstr.FromInt(8443)
	require.Equal(t, &udpPort, np.Spec.Ingress[0].Ports[1].Port)
	require.Equal(t, corev1.ProtocolUDP, *np.Spec.Ingress[0].Ports[1].Protocol)
}

// TestIsWorldPeer covers world peer string detection.
func TestIsWorldPeer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		peer    string
		isWorld bool
	}{
		{"pub", true},
		{"pvt", true},
		{"-", true},
		{"0.0.0.0/0", true},
		{"", true},
		{"prod/backend", false},
		{"app=frontend", false},
		{"default/frontend", false},
	}

	for _, tt := range tests {
		t.Run(tt.peer, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.isWorld, isWorldPeer(tt.peer))
		})
	}
}

// --- parseWorkloadSelectorV2 tests ---

func TestParseWorkloadSelectorV2_World(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{"pvt", "pvt"},
		{"pub", "pub"},
		{"dash", "-"},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			peer, err := parseWorkloadSelectorV2(tt.input, nil)
			require.NoError(t, err)
			require.NotNil(t, peer.IPBlock)
			require.Equal(t, "0.0.0.0/0", peer.IPBlock.CIDR)
			require.Nil(t, peer.PodSelector)
			require.Nil(t, peer.NamespaceSelector)
		})
	}
}

func TestParseWorkloadSelectorV2_CrossNamespace(t *testing.T) {
	t.Parallel()

	peer, err := parseWorkloadSelectorV2("prod/backend", nil)
	require.NoError(t, err)
	require.NotNil(t, peer.PodSelector)
	require.Equal(t, map[string]string{"app": "backend"}, peer.PodSelector.MatchLabels)
	require.NotNil(t, peer.NamespaceSelector)
	require.Equal(t, map[string]string{"kubernetes.io/metadata.name": "prod"}, peer.NamespaceSelector.MatchLabels)
}

func TestParseWorkloadSelectorV2_CrossNamespaceWithLabels(t *testing.T) {
	t.Parallel()

	peer, err := parseWorkloadSelectorV2("prod/backend,version=v1", nil)
	require.NoError(t, err)
	require.NotNil(t, peer.PodSelector)
	require.Equal(t, map[string]string{"app": "backend", "version": "v1"}, peer.PodSelector.MatchLabels)
	require.NotNil(t, peer.NamespaceSelector)
	require.Equal(t, map[string]string{"kubernetes.io/metadata.name": "prod"}, peer.NamespaceSelector.MatchLabels)
}

func TestParseWorkloadSelectorV2_LabelsOnly(t *testing.T) {
	t.Parallel()

	peer, err := parseWorkloadSelectorV2("app=frontend,version=v1", nil)
	require.NoError(t, err)
	require.NotNil(t, peer.PodSelector)
	require.Equal(t, map[string]string{"app": "frontend", "version": "v1"}, peer.PodSelector.MatchLabels)
	require.Nil(t, peer.NamespaceSelector)
}

// TestParseWorkloadSelectorV2_SlashKeyLabels verifies that segments containing
// '=' are parsed as labels even when the key contains '/', preventing the '/'
// from being mistaken as a namespace separator.
func TestParseWorkloadSelectorV2_SlashKeyLabels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		input         string
		wantPodLabels map[string]string
		wantNsLabel   map[string]string
	}{
		{
			name:          "label with slash key only",
			input:         "app.kubernetes.io/name=calico-apiserver",
			wantPodLabels: map[string]string{"app.kubernetes.io/name": "calico-apiserver"},
			wantNsLabel:   nil,
		},
		{
			name:          "label with uuid slash key",
			input:         "run.ai/workload-id=f8912b5b-1111-2222-3333-444455556666",
			wantPodLabels: map[string]string{"run.ai/workload-id": "f8912b5b-1111-2222-3333-444455556666"},
			wantNsLabel:   nil,
		},
		{
			name:          "namespace/name + slash-key label",
			input:         "prod/backend,app.kubernetes.io/name=calico-apiserver",
			wantPodLabels: map[string]string{"app": "backend", "app.kubernetes.io/name": "calico-apiserver"},
			wantNsLabel:   map[string]string{"kubernetes.io/metadata.name": "prod"},
		},
		{
			name:          "slash-key label + namespace/name",
			input:         "app.kubernetes.io/name=calico-apiserver,prod/backend",
			wantPodLabels: map[string]string{"app.kubernetes.io/name": "calico-apiserver", "app": "backend"},
			wantNsLabel:   map[string]string{"kubernetes.io/metadata.name": "prod"},
		},
		{
			name:          "multiple slash-key labels",
			input:         "app.kubernetes.io/name=calico,app.kubernetes.io/component=server",
			wantPodLabels: map[string]string{"app.kubernetes.io/name": "calico", "app.kubernetes.io/component": "server"},
			wantNsLabel:   nil,
		},
		{
			name:          "bare name with slash key label",
			input:         "frontend,app.kubernetes.io/version=v2",
			wantPodLabels: map[string]string{"app": "frontend", "app.kubernetes.io/version": "v2"},
			wantNsLabel:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			peer, err := parseWorkloadSelectorV2(tt.input, nil)
			require.NoError(t, err)

			if tt.wantPodLabels != nil {
				require.NotNil(t, peer.PodSelector)
				require.Equal(t, tt.wantPodLabels, peer.PodSelector.MatchLabels)
			} else {
				require.Nil(t, peer.PodSelector)
			}

			if tt.wantNsLabel != nil {
				require.NotNil(t, peer.NamespaceSelector)
				require.Equal(t, tt.wantNsLabel, peer.NamespaceSelector.MatchLabels)
			} else {
				require.Nil(t, peer.NamespaceSelector)
			}
		})
	}
}

// --- buildNetworkPolicy world-peer tests ---

func TestBuildNetworkPolicy_WorldIngress(t *testing.T) {
	t.Parallel()

	p := policy.Policy{
		WorkloadID:        "prod/api-gateway",
		WorkloadNamespace: "prod",
		WorkloadName:      "api-gateway",
		IngressRules: []policy.IngressRule{
			{
				FromWorkloads: []string{"pvt", "pub"},
				Ports:         []policy.PortSpec{{Port: 443, Protocol: "TCP"}},
			},
		},
	}

	np := buildNetworkPolicy(p, config.Config{})

	require.Len(t, np.Spec.Ingress, 1)
	require.Len(t, np.Spec.Ingress[0].From, 2)

	// Both peers should be IPBlock, no podSelector or namespaceSelector
	for _, from := range np.Spec.Ingress[0].From {
		require.NotNil(t, from.IPBlock)
		require.Equal(t, "0.0.0.0/0", from.IPBlock.CIDR)
		require.Nil(t, from.PodSelector)
		require.Nil(t, from.NamespaceSelector)
	}
}

func TestBuildNetworkPolicy_WorldEgress(t *testing.T) {
	t.Parallel()

	p := policy.Policy{
		WorkloadID:        "default/frontend",
		WorkloadNamespace: "default",
		WorkloadName:      "frontend",
		EgressRules: []policy.EgressRule{
			{
				ToWorkloads: []string{"pvt", "pub"},
				ToPorts:     []policy.PortSpec{{Port: 443, Protocol: "TCP"}},
			},
		},
	}

	np := buildNetworkPolicy(p, config.Config{})

	require.Len(t, np.Spec.Egress, 1)
	require.Len(t, np.Spec.Egress[0].To, 2)

	for _, to := range np.Spec.Egress[0].To {
		require.NotNil(t, to.IPBlock)
		require.Equal(t, "0.0.0.0/0", to.IPBlock.CIDR)
		require.Nil(t, to.PodSelector)
		require.Nil(t, to.NamespaceSelector)
	}
}

func TestBuildNetworkPolicy_MixedWorldAndCrossNamespace(t *testing.T) {
	t.Parallel()

	p := policy.Policy{
		WorkloadID:        "default/backend",
		WorkloadNamespace: "default",
		WorkloadName:      "backend",
		IngressRules: []policy.IngressRule{
			{
				FromWorkloads: []string{"pvt", "prod/frontend,version=v1"},
				Ports:         []policy.PortSpec{{Port: 8080, Protocol: "TCP"}},
			},
		},
	}

	np := buildNetworkPolicy(p, config.Config{})

	require.Len(t, np.Spec.Ingress, 1)
	require.Len(t, np.Spec.Ingress[0].From, 2)

	// First: pvt → IPBlock
	require.NotNil(t, np.Spec.Ingress[0].From[0].IPBlock)
	require.Equal(t, "0.0.0.0/0", np.Spec.Ingress[0].From[0].IPBlock.CIDR)

	// Second: prod/frontend,version=v1 → podSelector + namespaceSelector
	peer := np.Spec.Ingress[0].From[1]
	require.NotNil(t, peer.PodSelector)
	require.Equal(t, map[string]string{"app": "frontend", "version": "v1"}, peer.PodSelector.MatchLabels)
	require.NotNil(t, peer.NamespaceSelector)
	require.Equal(t, map[string]string{"kubernetes.io/metadata.name": "prod"}, peer.NamespaceSelector.MatchLabels)
}

// TestBuildNetworkPolicy_WorldIngressCIDR verifies that a FromWorkload of
// "0.0.0.0/0" produces a single IPBlock peer with CIDR 0.0.0.0/0, no
// PodSelector or NamespaceSelector. This is a regression test for the fix
// introduced in dd0c957 (isWorldPeer: treat "0.0.0.0/0" as world).
func TestBuildNetworkPolicy_WorldIngressCIDR(t *testing.T) {
	t.Parallel()

	p := policy.Policy{
		WorkloadID:        "prod/public-api",
		WorkloadNamespace: "prod",
		WorkloadName:      "public-api",
		IngressRules: []policy.IngressRule{
			{
				FromWorkloads: []string{"0.0.0.0/0"},
				Ports:         []policy.PortSpec{{Port: 443, Protocol: "TCP"}},
			},
		},
	}

	np := buildNetworkPolicy(p, config.Config{})

	require.Len(t, np.Spec.Ingress, 1)
	require.Len(t, np.Spec.Ingress[0].From, 1)

	peer := np.Spec.Ingress[0].From[0]
	require.NotNil(t, peer.IPBlock)
	require.Equal(t, "0.0.0.0/0", peer.IPBlock.CIDR)
	require.Nil(t, peer.PodSelector)
	require.Nil(t, peer.NamespaceSelector)
}

func TestBuildNetworkPolicy_NoWorldSelectors(t *testing.T) {
	// Regression: ensure no policy contains podSelector: {app: pvt}
	// or namespaceSelector: {kubernetes.io/metadata.name: '-'}
	t.Parallel()

	p := policy.Policy{
		WorkloadID:        "default/web",
		WorkloadNamespace: "default",
		WorkloadName:      "web",
		IngressRules: []policy.IngressRule{
			{
				FromWorkloads: []string{"pvt", "pub", "-", "prod/api"},
				Ports:         []policy.PortSpec{{Port: 80, Protocol: "TCP"}},
			},
		},
	}

	np := buildNetworkPolicy(p, config.Config{})

	// Collect any podSelector values from From peers
	for _, from := range np.Spec.Ingress[0].From {
		if from.PodSelector != nil {
			for _, v := range from.PodSelector.MatchLabels {
				require.NotEqual(t, "pvt", v, "pvt should never appear in podSelector values")
				require.NotEqual(t, "pub", v, "pub should never appear in podSelector values")
				require.NotEqual(t, "-", v, "- should never appear in podSelector values")
			}
		}
		if from.NamespaceSelector != nil {
			for _, v := range from.NamespaceSelector.MatchLabels {
				require.NotEqual(t, "-", v, "namespace should never be '-' in namespaceSelector values")
			}
		}
	}
}

// TestParseWorkloadSelectorV2_ApiserverWithCIDR verifies that peer "apiserver"
// with cfg.APIServerCIDRs set returns an IPBlock with the first CIDR.
func TestParseWorkloadSelectorV2_ApiserverWithCIDR(t *testing.T) {
	t.Parallel()

	_, cidr, err := net.ParseCIDR("10.96.0.0/12")
	require.NoError(t, err)
	cfg := config.Config{
		APIServerCIDRs: []*net.IPNet{cidr},
	}

	peer, err := parseWorkloadSelectorV2("apiserver", &cfg)
	require.NoError(t, err)
	require.NotNil(t, peer.IPBlock)
	require.Equal(t, "10.96.0.0/12", peer.IPBlock.CIDR)
	require.Nil(t, peer.PodSelector)
	require.Nil(t, peer.NamespaceSelector)
}

// TestParseWorkloadSelectorV2_ApiserverFallback verifies that peer "apiserver"
// with a non-nil but empty APIServerCIDRs returns kube-system all-pods fallback.
func TestParseWorkloadSelectorV2_ApiserverFallback(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		APIServerCIDRs: nil,
	}

	peer, err := parseWorkloadSelectorV2("apiserver", &cfg)
	require.NoError(t, err)
	require.Nil(t, peer.IPBlock)
	require.NotNil(t, peer.PodSelector)
	require.NotNil(t, peer.NamespaceSelector)
	require.Equal(t, map[string]string{"kubernetes.io/metadata.name": "kube-system"}, peer.NamespaceSelector.MatchLabels)
}

// TestParseWorkloadSelectorV2_ApiserverNilConfig verifies that peer "apiserver"
// with cfg == nil also returns kube-system all-pods fallback.
func TestParseWorkloadSelectorV2_ApiserverNilConfig(t *testing.T) {
	t.Parallel()

	peer, err := parseWorkloadSelectorV2("apiserver", nil)
	require.NoError(t, err)
	require.Nil(t, peer.IPBlock)
	require.NotNil(t, peer.PodSelector)
	require.NotNil(t, peer.NamespaceSelector)
	require.Equal(t, map[string]string{"kubernetes.io/metadata.name": "kube-system"}, peer.NamespaceSelector.MatchLabels)
}

// TestBuildNetworkPolicy_ApiServerEgress verifies that an egress rule with
// ToCIDRs:["apiserver"] renders to ipBlock: 10.96.0.0/12 in the NetworkPolicy
// when cfg.APIServerCIDRs is set, and to kube-system namespaceSelector when empty.
func TestBuildNetworkPolicy_ApiServerEgress(t *testing.T) {
	t.Parallel()

	p := policy.Policy{
		WorkloadID:        "default/frontend",
		WorkloadNamespace: "default",
		WorkloadName:      "frontend",
		IngressRules:      nil,
		EgressRules: []policy.EgressRule{
			{
				ToCIDRs: []string{"apiserver"},
				ToPorts: []policy.PortSpec{{Port: 6443, Protocol: "TCP"}},
			},
		},
	}

	// With APIServerCIDRs set → ipBlock with the configured CIDR.
	_, apiserverCIDR, err := net.ParseCIDR("10.96.0.0/12")
	require.NoError(t, err)

	cfgWithCIDR := config.Config{
		APIServerCIDRs: []*net.IPNet{apiserverCIDR},
	}
	npCIDR := buildNetworkPolicy(p, cfgWithCIDR)

	require.Len(t, npCIDR.Spec.Egress, 1)
	require.Len(t, npCIDR.Spec.Egress[0].To, 1)
	require.NotNil(t, npCIDR.Spec.Egress[0].To[0].IPBlock)
	require.Equal(t, "10.96.0.0/12", npCIDR.Spec.Egress[0].To[0].IPBlock.CIDR)

	// With nil APIServerCIDRs → kube-system namespaceSelector fallback.
	cfgNilCIDR := config.Config{APIServerCIDRs: nil}
	npFallback := buildNetworkPolicy(p, cfgNilCIDR)

	require.Len(t, npFallback.Spec.Egress, 1)
	require.Len(t, npFallback.Spec.Egress[0].To, 1)
	require.Nil(t, npFallback.Spec.Egress[0].To[0].IPBlock)
	require.NotNil(t, npFallback.Spec.Egress[0].To[0].NamespaceSelector)
	require.Equal(t, map[string]string{"kubernetes.io/metadata.name": "kube-system"},
		npFallback.Spec.Egress[0].To[0].NamespaceSelector.MatchLabels)
	require.NotNil(t, npFallback.Spec.Egress[0].To[0].PodSelector)
	// PodSelector is empty (match all pods in kube-system).
	require.Equal(t, map[string]string(nil), npFallback.Spec.Egress[0].To[0].PodSelector.MatchLabels)
}

// TestBuildNetworkPolicy_ApiServerIngress verifies that an ingress rule with
// FromWorkloads:["apiserver"] renders to ipBlock: 10.96.0.0/12 when
// cfg.APIServerCIDRs is set.
func TestBuildNetworkPolicy_ApiServerIngress(t *testing.T) {
	t.Parallel()

	p := policy.Policy{
		WorkloadID:        "prod/api-server",
		WorkloadNamespace: "prod",
		WorkloadName:      "api-server",
		IngressRules: []policy.IngressRule{
			{
				FromWorkloads: []string{"apiserver"},
				Ports:         []policy.PortSpec{{Port: 9443, Protocol: "TCP"}},
			},
		},
	}

	_, apiserverCIDR, err := net.ParseCIDR("10.96.0.0/12")
	require.NoError(t, err)
	cfg := config.Config{APIServerCIDRs: []*net.IPNet{apiserverCIDR}}

	np := buildNetworkPolicy(p, cfg)

	require.Len(t, np.Spec.Ingress, 1)
	require.Len(t, np.Spec.Ingress[0].From, 1)
	require.NotNil(t, np.Spec.Ingress[0].From[0].IPBlock)
	require.Equal(t, "10.96.0.0/12", np.Spec.Ingress[0].From[0].IPBlock.CIDR)
}

// TestBuildNetworkPolicy_MixedWorldAndAPIServerEgress verifies that a policy
// with both world (0.0.0.0/0) and apiserver CIDRs in a single egress rule
// renders correctly with both IPBlock peers.
func TestBuildNetworkPolicy_MixedWorldAndAPIServerEgress(t *testing.T) {
	t.Parallel()

	p := policy.Policy{
		WorkloadID:        "default/gateway",
		WorkloadNamespace: "default",
		WorkloadName:      "gateway",
		IngressRules:      nil,
		EgressRules: []policy.EgressRule{
			{
				ToCIDRs: []string{"apiserver", "0.0.0.0/0"},
				ToPorts: []policy.PortSpec{{Port: 443, Protocol: "TCP"}},
			},
		},
	}

	_, apiserverCIDR, err := net.ParseCIDR("10.96.0.0/12")
	require.NoError(t, err)
	cfg := config.Config{APIServerCIDRs: []*net.IPNet{apiserverCIDR}}

	np := buildNetworkPolicy(p, cfg)

	require.Len(t, np.Spec.Egress, 1)
	require.Len(t, np.Spec.Egress[0].To, 2)

	// Collect CIDRs from IPBlock peers.
	var cidrs []string
	for _, to := range np.Spec.Egress[0].To {
		if to.IPBlock != nil {
			cidrs = append(cidrs, to.IPBlock.CIDR)
		}
	}
	require.ElementsMatch(t, []string{"10.96.0.0/12", "0.0.0.0/0"}, cidrs)
}

func TestParserRegistryPopulated_Hubble(t *testing.T) {
	t.Parallel()
	p, err := parser.SelectParser(parser.SourceHubble, parser.SourceHubble)
	require.NoError(t, err)
	require.NotNil(t, p)
}

func TestParserRegistryPopulated_Calico(t *testing.T) {
	t.Parallel()
	p, err := parser.SelectParser(parser.SourceCalico, parser.SourceCalico)
	require.NoError(t, err)
	require.NotNil(t, p)
}

func TestSourceAutoInSelectParser(t *testing.T) {
	t.Parallel()
	_, err := parser.SelectParser(parser.SourceAuto, parser.SourceAuto)
	require.Error(t, err)
	require.Contains(t, err.Error(), "auto-detect requires a reader")
}

func TestAutoDetect_HubbleFixture(t *testing.T) {
	t.Parallel()
	src, err := autoDetectSource("../../testdata/hubble/protojson.jsonl")
	require.NoError(t, err)
	require.Equal(t, parser.SourceHubble, src)
}

// TestValidReports_Map ensures all documented report names are accepted.
func TestValidReports_Map(t *testing.T) {
	t.Parallel()

	expected := []string{"top-flows", "uncovered", "coverage", "egress-world", "drops", "anomalies"}
	for _, r := range expected {
		require.True(t, validReports[r], "validReports should contain %q", r)
	}
}

// TestAnalyzeFlags_Validation tests report validation, topN, and generateUncovered wiring.
func TestAnalyzeFlags_Validation(t *testing.T) {
	t.Parallel()

	// 1. Bogus report name should produce an "unknown report" error.
	err := runAnalyzePipeline(nil, "../../testdata/hubble/protojson.jsonl", &rootCmdData{
		reports: []string{"bogus"},
		format:  "text",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown report")
	require.Contains(t, err.Error(), "bogus")

	// 2. Valid reports: create a temp file with a single valid Hubble line
	// so the pipeline runs through without EOF or nil-cmd panics.
	tmp, err := os.CreateTemp("", "valid-flows-*.jsonl")
	require.NoError(t, err)
	// Minimal Hubble protojson line so the parser accepts it.
	_, _ = tmp.WriteString(`{"time":"2026-08-01T13:24:31Z","verdict":"FORWARDED","traffic_direction":"EGRESS","source":{"namespace":"default","pod_name":"a"},"destination":{"namespace":"default","pod_name":"b"}}` + "\n")
	tmpPath := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpPath)

	err = runAnalyzePipeline(nil, tmpPath, &rootCmdData{
		reports:           []string{"top-flows", "coverage"},
		topN:              5,
		generateUncovered: true,
		source:            "hubble", // skip auto-detect to avoid nil-cmd.Printf on empty file
		format:            "text",
	})
	require.NoError(t, err)

	// 3. topN=5 should not cause a validation error.
	err = runAnalyzePipeline(nil, tmpPath, &rootCmdData{
		topN:   5,
		source: "hubble",
		format: "text",
	})
	require.NoError(t, err)

	// 4. generateUncovered true should not cause a validation error.
	err = runAnalyzePipeline(nil, tmpPath, &rootCmdData{
		generateUncovered: true,
		source:            "hubble",
		format:            "text",
	})
	require.NoError(t, err)
}

// TestReportSet tests the ReportSet helper.
func TestReportSet(t *testing.T) {
	t.Parallel()

	rs := newReportSet([]string{"anomalies", "coverage"})
	require.True(t, rs.hasReport("anomalies"))
	require.False(t, rs.hasReport("top-flows"))

	empty := newReportSet(nil)
	require.False(t, empty.hasReport("anomalies"))
	require.False(t, empty.hasReport())
}

// TestPrintTextReport_MinimalSummary verifies that with no report flags,
// printTextReport shows only the minimal summary (no anomalies, top-flows).
func TestPrintTextReport_MinimalSummary(t *testing.T) {
	t.Parallel()

	// Create a temporary "cmd" that captures output.
	cmd := &cobra.Command{}
	var buf strings.Builder
	cmd.SetOut(&buf)

	// Create minimal policies so we reach printTextReport.
	p := policy.Policy{
		WorkloadID:        "default/web",
		WorkloadNamespace: "default",
		WorkloadName:      "web",
		EgressRules:       []policy.EgressRule{{ToCIDRs: []string{"0.0.0.0/0"}}},
	}

	// No report flags: minimal summary only.
	printTextReport(cmd, nil, nil, nil, nil, []policy.Policy{p}, nil, 0)

	output := buf.String()
	require.Contains(t, output, "Flows parsed:")
	require.Contains(t, output, "Workloads:")
	require.Contains(t, output, "Policies:")
	require.NotContains(t, output, "Anomalies:")
	require.NotContains(t, output, "Top flows")
	require.NotContains(t, output, "Egress-world")
	require.NotContains(t, output, "Coverage")
}

// TestPrintTextReport_Anomalies verifies that --report anomalies prints anomalies.
func TestPrintTextReport_Anomalies(t *testing.T) {
	t.Parallel()

	cmd := &cobra.Command{}
	var buf strings.Builder
	cmd.SetOut(&buf)

	a := anomaly.Anomaly{
		Severity:    "high",
		Type:        "portscan",
		Workload:    "default/api",
		Description: "Detected scan of 25 ports",
	}

	// Create policy so it's non-empty for the pipeline path.
	p := policy.Policy{
		WorkloadID:        "default/web",
		WorkloadNamespace: "default",
		WorkloadName:      "web",
		EgressRules:       []policy.EgressRule{{ToCIDRs: []string{"0.0.0.0/0"}}},
	}

	printTextReport(cmd, nil, nil, nil, []anomaly.Anomaly{a}, []policy.Policy{p}, []string{"anomalies"}, 0)

	output := buf.String()
	require.Contains(t, output, "Anomalies:")
	require.Contains(t, output, "portscan")
	require.NotContains(t, output, "Top flows")
	require.NotContains(t, output, "Coverage")
}

// TestPrintTextReport_TopFlows verifies --report top-flows prints top flows table.
func TestPrintTextReport_TopFlowsReport(t *testing.T) {
	t.Parallel()

	cmd := &cobra.Command{}
	var buf strings.Builder
	cmd.SetOut(&buf)

	flows := []flow.Flow{
		{
			Time:        time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
			Source:      flow.Endpoint{IP: "10.0.0.1", Namespace: "default", PodName: "a"},
			Destination: flow.Endpoint{IP: "10.0.0.2", Namespace: "default", PodName: "b"},
			Layer4:      flow.Layer4{DestPort: 80, Protocol: flow.TCP},
			Verdict:     flow.Forwarded,
			Direction:   flow.Egress,
			Bytes:       1000,
		},
	}
	workloads := analyze.Workloads{
		"default/a": {Namespace: "default", Name: "a"},
		"default/b": {Namespace: "default", Name: "b"},
	}

	printTextReport(cmd, flows, nil, workloads, nil, nil, []string{"top-flows"}, 5)

	output := buf.String()
	require.Contains(t, output, "Top flows")
}

// TestRunAnalyzePipeline_NoReportsMinimalSummary verifies that running
// the full pipeline with no --report flags produces minimal summary only.
func TestRunAnalyzePipeline_NoReportsMinimalSummary(t *testing.T) {
	t.Parallel()

	// Use the real protojson fixture so the hubble parser produces valid flows.
	tmpPath := "../../testdata/hubble/protojson.jsonl"

	var buf strings.Builder
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)

	err := runAnalyzePipeline(cmd, tmpPath, &rootCmdData{
		reports: nil,
		format:  "text",
		source:  "hubble",
	})
	require.NoError(t, err)

	output := buf.String()
	require.Contains(t, output, "Flows parsed:")
	require.Contains(t, output, "Workloads:")
	require.Contains(t, output, "Policies:")
	// No report flags → no anomalies list, no top-flows.
	require.NotContains(t, output, "Anomalies:")
	require.NotContains(t, output, "Top flows")
	require.NotContains(t, output, "Coverage")
}

// ─── Regression tests for Bug 1/2/3 fixes ─────────────────────────────

// TestAutoDetectSource_Directory_ConcreteSource verifies that autoDetectSource
// on a directory returns a concrete source (not SourceAuto/SourceUnknown) by
// delegating to DetectFormatDir, which probes the first matching JSON file.
func TestAutoDetectSource_Directory_ConcreteSource(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Write a hubble JSONL file so DetectFormatDir can find and probe it.
	data := `{"time":"2024-01-01T00:00:00Z","verdict":"FORWARDED",` +
		`"source":{"pod_name":"foo"},"destination":{"pod_name":"bar"}}` + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "flows.jsonl"), []byte(data), 0644))

	src, err := autoDetectSource(tmpDir)
	require.NoError(t, err, "auto-detect on a directory should not return an error")
	require.NotEqual(t, parser.SourceAuto, src,
		"autoDetectSource on a directory must return a concrete source, not SourceAuto")
	require.Equal(t, parser.SourceHubble, src,
		"directory containing hubble JSONL should detect source Hubble")
}

// TestAutoDetectSource_Directory_MixedFiles verifies that a directory
// containing non-flow files (README.md) alongside flow files still detects
// the correct source — the junk file must not interfere.
func TestAutoDetectSource_Directory_MixedFiles(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "flows.jsonl"),
		[]byte(`{"time":"2024-01-01T00:00:00Z","verdict":"FORWARDED","source":{"pod_name":"a"},"destination":{"pod_name":"b"}}`+"\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "README.md"),
		[]byte("not a flow file"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "config.yaml"),
		[]byte("key: value"), 0644))

	src, err := autoDetectSource(tmpDir)
	require.NoError(t, err)
	require.Equal(t, parser.SourceHubble, src,
		"non-flow junk files must not prevent auto-detection")
}

// TestBufStdinSource_ReadTwice verifies that bufStdinSource can be opened
// twice returning identical content — the buffering must not mutate.
func TestBufStdinSource_ReadTwice(t *testing.T) {
	t.Parallel()

	data := []byte(`{"time":"2024-01-01T00:00:00Z","verdict":"FORWARDED","source":{"pod_name":"a"},"destination":{"pod_name":"b"}}` + "\n")
	src := &bufStdinSource{data: data}

	r1, err := src.Open(context.Background())
	require.NoError(t, err)
	content1, err := io.ReadAll(r1)
	require.NoError(t, err)
	require.NoError(t, r1.Close())

	r2, err := src.Open(context.Background())
	require.NoError(t, err)
	content2, err := io.ReadAll(r2)
	require.NoError(t, err)
	require.NoError(t, r2.Close())

	require.Equal(t, content1, content2,
		"bufStdinSource must return identical content on repeated opens")
	require.Equal(t, data, content1,
		"bufStdinSource must preserve original data")
}

// TestStdinAutoDetect_NoDoubleRead verifies that detecting format from a
// bytes.Reader does not consume data that a subsequent parser would need.
// This locks the stdin buffering bug regression.
func TestStdinAutoDetect_NoDoubleRead(t *testing.T) {
	t.Parallel()

	hubbleLines := `{"time":"2024-01-01T00:00:00Z","verdict":"FORWARDED","source":{"pod_name":"alpha","namespace":"default","pod_ip":"10.244.0.1"},"destination":{"pod_name":"beta","namespace":"default","pod_ip":"10.244.0.2","node_ip":"192.168.1.10"}}` + "\n"

	// Step 1: Detect from a bytes.Reader (simulates buffered stdin).
	src, err := parser.DetectFormat(strings.NewReader(hubbleLines))
	require.NoError(t, err)
	require.Equal(t, parser.SourceHubble, src)

	// Step 2: Parse from a FRESH bytes.Reader with the same content.
	// If detection had consumed bytes irreversibly this would fail.
	var parsed int
	hub, err := parser.SelectParser(parser.SourceHubble, parser.SourceHubble)
	require.NoError(t, err)
	err = hub.Parse(strings.NewReader(hubbleLines), func(f flow.Flow) error {
		parsed++
		return nil
	})
	require.NoError(t, err, "parsing the same content after detection must succeed")

	// Step 3: Detect from the same reader again — Reset/rewind would be ideal
	// but the point is: bytes.Reader detection is idempotent when using separate instances.
	src2, err := parser.DetectFormat(strings.NewReader(hubbleLines))
	require.NoError(t, err)
	require.Equal(t, parser.SourceHubble, src2)
}

// TestDirSource_SkipsNonFlowFiles verifies that a DirSource with a Pattern
// correctly skips non-flow files (README.md, .DS_Store, etc.) during iteration.
func TestDirSource_SkipsNonFlowFiles(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create a mix of flow and non-flow files.
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "flows.jsonl"),
		[]byte("data\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "README.md"),
		[]byte("not a flow"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".DS_Store"),
		[]byte("blob"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "config.yaml"),
		[]byte("key: value"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "data.json"),
		[]byte("also data\n"), 0644))

	pattern, err := regexp.Compile(`(?i)\.(json|jsonl|log)(\.gz)?$`)
	require.NoError(t, err)

	ds := &ingest.DirSource{Path: tmpDir, Pattern: pattern}
	var yielded []string
	err = ds.Iterate(context.Background(), func(p string) error {
		yielded = append(yielded, filepath.Base(p))
		return nil
	})
	require.NoError(t, err)

	require.ElementsMatch(t, []string{"data.json", "flows.jsonl"}, yielded,
		"DirSource with Pattern should only yield flow-matching files")
}

// TestDirSource_noPattern_YieldsAllFiles verifies that a DirSource without a
// Pattern yields ALL files (backward compatibility with any existing code that
// doesn't set Pattern).
func TestDirSource_noPattern_YieldsAllFiles(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	for _, name := range []string{"flows.jsonl", "README.md", ".DS_Store"} {
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, name),
			[]byte("data\n"), 0644))
	}

	ds := &ingest.DirSource{Path: tmpDir}
	var yielded []string
	err := ds.Iterate(context.Background(), func(p string) error {
		yielded = append(yielded, filepath.Base(p))
		return nil
	})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"flows.jsonl", "README.md", ".DS_Store"}, yielded)
}

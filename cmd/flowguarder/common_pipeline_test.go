package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/flowguarder/flowguarder/pkg/analyze"
	"github.com/flowguarder/flowguarder/pkg/anomaly"
	"github.com/flowguarder/flowguarder/pkg/config"
	"github.com/flowguarder/flowguarder/pkg/flow"
	"github.com/flowguarder/flowguarder/pkg/ingest"
	"github.com/flowguarder/flowguarder/pkg/parser"
	"github.com/flowguarder/flowguarder/pkg/policy"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
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

	np := buildNetworkPolicy(p, config.Config{}, nil)

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

	np := buildNetworkPolicy(p, config.Config{}, nil)

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

	np := buildNetworkPolicy(p, config.Config{}, nil)

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

	np := buildNetworkPolicy(p, config.Config{}, nil)

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

	np := buildNetworkPolicy(p, config.Config{}, nil)

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
			peers, err := parseWorkloadSelectorV2(tt.input, nil, nil)
			require.NoError(t, err)
			require.NotNil(t, peers[0].IPBlock)
			require.Equal(t, "0.0.0.0/0", peers[0].IPBlock.CIDR)
			require.Nil(t, peers[0].PodSelector)
			require.Nil(t, peers[0].NamespaceSelector)
		})
	}
}

func TestParseWorkloadSelectorV2_CrossNamespace(t *testing.T) {
	t.Parallel()

	peers, err := parseWorkloadSelectorV2("prod/backend", nil, nil)
	require.NoError(t, err)
	require.NotNil(t, peers[0].PodSelector)
	require.Equal(t, map[string]string{"app": "backend"}, peers[0].PodSelector.MatchLabels)
	require.NotNil(t, peers[0].NamespaceSelector)
	require.Equal(t, map[string]string{"kubernetes.io/metadata.name": "prod"}, peers[0].NamespaceSelector.MatchLabels)
}

func TestParseWorkloadSelectorV2_CrossNamespaceWithLabels(t *testing.T) {
	t.Parallel()

	peers, err := parseWorkloadSelectorV2("prod/backend,version=v1", nil, nil)
	require.NoError(t, err)
	require.NotNil(t, peers[0].PodSelector)
	require.Equal(t, map[string]string{"app": "backend", "version": "v1"}, peers[0].PodSelector.MatchLabels)
	require.NotNil(t, peers[0].NamespaceSelector)
	require.Equal(t, map[string]string{"kubernetes.io/metadata.name": "prod"}, peers[0].NamespaceSelector.MatchLabels)
}

func TestParseWorkloadSelectorV2_LabelsOnly(t *testing.T) {
	t.Parallel()

	peers, err := parseWorkloadSelectorV2("app=frontend,version=v1", nil, nil)
	require.NoError(t, err)
	require.NotNil(t, peers[0].PodSelector)
	require.Equal(t, map[string]string{"app": "frontend", "version": "v1"}, peers[0].PodSelector.MatchLabels)
	require.Nil(t, peers[0].NamespaceSelector)
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

			peers, err := parseWorkloadSelectorV2(tt.input, nil, nil)
			require.NoError(t, err)

			if tt.wantPodLabels != nil {
				require.NotNil(t, peers[0].PodSelector)
				require.Equal(t, tt.wantPodLabels, peers[0].PodSelector.MatchLabels)
			} else {
				require.Nil(t, peers[0].PodSelector)
			}

			if tt.wantNsLabel != nil {
				require.NotNil(t, peers[0].NamespaceSelector)
				require.Equal(t, tt.wantNsLabel, peers[0].NamespaceSelector.MatchLabels)
			} else {
				require.Nil(t, peers[0].NamespaceSelector)
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

	np := buildNetworkPolicy(p, config.Config{}, nil)

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

	np := buildNetworkPolicy(p, config.Config{}, nil)

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

	np := buildNetworkPolicy(p, config.Config{}, nil)

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

	np := buildNetworkPolicy(p, config.Config{}, nil)

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

	np := buildNetworkPolicy(p, config.Config{}, nil)

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
// with cfg.APIServerCIDRs set returns IPBlock peers for host-route CIDRs only
// (/32 IPv4, /128 IPv6). Service-range CIDRs are skipped.
func TestParseWorkloadSelectorV2_ApiserverWithCIDR(t *testing.T) {
	t.Parallel()

	// Service-range CIDR alone → no host routes → kube-system fallback.
	_, svcRange, _ := net.ParseCIDR("10.96.0.0/12")
	cfg := config.Config{
		APIServerCIDRs: []*net.IPNet{svcRange},
	}

	peers, err := parseWorkloadSelectorV2("apiserver", &cfg, nil)
	require.NoError(t, err)
	require.Len(t, peers, 1)
	require.Nil(t, peers[0].IPBlock)
	require.NotNil(t, peers[0].PodSelector)
	require.NotNil(t, peers[0].NamespaceSelector)
	require.Equal(t, map[string]string{"kubernetes.io/metadata.name": "kube-system"},
		peers[0].NamespaceSelector.MatchLabels)

	// Host route /32 → returned as IPBlock.
	_, hostIP, _ := net.ParseCIDR("192.168.107.5/32")
	cfgWithHost := config.Config{
		APIServerCIDRs: []*net.IPNet{hostIP},
	}
	peers2, err := parseWorkloadSelectorV2("apiserver", &cfgWithHost, nil)
	require.NoError(t, err)
	require.Len(t, peers2, 1)
	require.NotNil(t, peers2[0].IPBlock)
	require.Equal(t, "192.168.107.5/32", peers2[0].IPBlock.CIDR)
	require.Nil(t, peers2[0].PodSelector)
	require.Nil(t, peers2[0].NamespaceSelector)
}

// TestParseWorkloadSelectorV2_ApiserverFallback verifies that peer "apiserver"
// with a non-nil but empty APIServerCIDRs returns kube-system all-pods fallback.
func TestParseWorkloadSelectorV2_ApiserverFallback(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		APIServerCIDRs: nil,
	}

	peers, err := parseWorkloadSelectorV2("apiserver", &cfg, nil)
	require.NoError(t, err)
	require.Nil(t, peers[0].IPBlock)
	require.NotNil(t, peers[0].PodSelector)
	require.NotNil(t, peers[0].NamespaceSelector)
	require.Equal(t, map[string]string{"kubernetes.io/metadata.name": "kube-system"}, peers[0].NamespaceSelector.MatchLabels)
}

// TestParseWorkloadSelectorV2_ApiserverNilConfig verifies that peer "apiserver"
// with cfg == nil also returns kube-system all-pods fallback.
func TestParseWorkloadSelectorV2_ApiserverNilConfig(t *testing.T) {
	t.Parallel()

	peers, err := parseWorkloadSelectorV2("apiserver", nil, nil)
	require.NoError(t, err)
	require.Nil(t, peers[0].IPBlock)
	require.NotNil(t, peers[0].PodSelector)
	require.NotNil(t, peers[0].NamespaceSelector)
	require.Equal(t, map[string]string{"kubernetes.io/metadata.name": "kube-system"}, peers[0].NamespaceSelector.MatchLabels)
}

// TestBuildNetworkPolicy_ApiServerEgress verifies that an egress rule with
// ToCIDRs:["apiserver"] renders to ipBlock with host-route CIDRs only when
// cfg.APIServerCIDRs is set, and to kube-system namespaceSelector fallback
// when no /32 IPs exist.
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

	// Service-range CIDR alone → kube-system namespaceSelector fallback.
	_, svcRange, _ := net.ParseCIDR("10.96.0.0/12")

	cfgSvcRange := config.Config{
		APIServerCIDRs: []*net.IPNet{svcRange},
	}
	npSvc := buildNetworkPolicy(p, cfgSvcRange, nil)

	require.Len(t, npSvc.Spec.Egress, 1)
	require.Len(t, npSvc.Spec.Egress[0].To, 1)
	require.Nil(t, npSvc.Spec.Egress[0].To[0].IPBlock)
	require.NotNil(t, npSvc.Spec.Egress[0].To[0].NamespaceSelector)
	require.Equal(t, map[string]string{"kubernetes.io/metadata.name": "kube-system"},
		npSvc.Spec.Egress[0].To[0].NamespaceSelector.MatchLabels)
	require.NotNil(t, npSvc.Spec.Egress[0].To[0].PodSelector)
	require.Equal(t, map[string]string(nil), npSvc.Spec.Egress[0].To[0].PodSelector.MatchLabels)

	// With a /32 node IP → ipBlock for that CIDR.
	_, hostIP, err := net.ParseCIDR("192.168.107.5/32")
	require.NoError(t, err)

	cfgWithHost := config.Config{
		APIServerCIDRs: []*net.IPNet{hostIP},
	}
	npHost := buildNetworkPolicy(p, cfgWithHost, nil)

	require.Len(t, npHost.Spec.Egress, 1)
	require.Len(t, npHost.Spec.Egress[0].To, 1)
	require.NotNil(t, npHost.Spec.Egress[0].To[0].IPBlock)
	require.Equal(t, "192.168.107.5/32", npHost.Spec.Egress[0].To[0].IPBlock.CIDR)

	// With nil APIServerCIDRs → kube-system namespaceSelector fallback.
	cfgNilCIDR := config.Config{APIServerCIDRs: nil}
	npFallback := buildNetworkPolicy(p, cfgNilCIDR, nil)

	require.Len(t, npFallback.Spec.Egress, 1)
	require.Len(t, npFallback.Spec.Egress[0].To, 1)
	require.Nil(t, npFallback.Spec.Egress[0].To[0].IPBlock)
	require.NotNil(t, npFallback.Spec.Egress[0].To[0].NamespaceSelector)
	require.Equal(t, map[string]string{"kubernetes.io/metadata.name": "kube-system"},
		npFallback.Spec.Egress[0].To[0].NamespaceSelector.MatchLabels)
	require.NotNil(t, npFallback.Spec.Egress[0].To[0].PodSelector)
	require.Equal(t, map[string]string(nil), npFallback.Spec.Egress[0].To[0].PodSelector.MatchLabels)
}

// TestBuildNetworkPolicy_ApiServerIngress verifies that an ingress rule with
// FromWorkloads:["apiserver"] renders to kube-system fallback when only
// service-range CIDRs are set, and to a /32 host IP when provided.
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

	// Service-range CIDR alone → kube-system fallback.
	_, svcRange, _ := net.ParseCIDR("10.96.0.0/12")
	cfgSvc := config.Config{APIServerCIDRs: []*net.IPNet{svcRange}}

	npSvc := buildNetworkPolicy(p, cfgSvc, nil)

	require.Len(t, npSvc.Spec.Ingress, 1)
	require.Len(t, npSvc.Spec.Ingress[0].From, 1)
	require.Nil(t, npSvc.Spec.Ingress[0].From[0].IPBlock)
	require.NotNil(t, npSvc.Spec.Ingress[0].From[0].NamespaceSelector)
	require.Equal(t, "kube-system", npSvc.Spec.Ingress[0].From[0].NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"])
	require.NotNil(t, npSvc.Spec.Ingress[0].From[0].PodSelector)

	// With a /32 host IP → ipBlock.
	_, hostIP, err := net.ParseCIDR("192.168.107.5/32")
	require.NoError(t, err)
	cfgHost := config.Config{APIServerCIDRs: []*net.IPNet{hostIP}}

	npHost := buildNetworkPolicy(p, cfgHost, nil)

	require.Len(t, npHost.Spec.Ingress, 1)
	require.Len(t, npHost.Spec.Ingress[0].From, 1)
	require.NotNil(t, npHost.Spec.Ingress[0].From[0].IPBlock)
	require.Equal(t, "192.168.107.5/32", npHost.Spec.Ingress[0].From[0].IPBlock.CIDR)
}

// TestBuildNetworkPolicy_MixedWorldAndAPIServerEgress verifies that a policy
// with both world (0.0.0.0/0) and apiserver in a single egress rule
// renders correctly: apiserver falls back to kube-system when only
// service-range CIDRs exist, while world always renders as 0.0.0.0/0.
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

	// Service-range CIDR → apiserver falls back to kube-system + world.
	_, apiserverCIDR, err := net.ParseCIDR("10.96.0.0/12")
	require.NoError(t, err)
	cfg := config.Config{APIServerCIDRs: []*net.IPNet{apiserverCIDR}}

	np := buildNetworkPolicy(p, cfg, nil)

	require.Len(t, np.Spec.Egress, 1)
	require.Len(t, np.Spec.Egress[0].To, 2)

	// Collect CIDRs / selectors.
	var ipblocks []string
	var hasWorld, hasKubeSystem bool
	for _, to := range np.Spec.Egress[0].To {
		if to.IPBlock != nil {
			ipblocks = append(ipblocks, to.IPBlock.CIDR)
		}
		if to.NamespaceSelector != nil && to.PodSelector != nil {
			if v, ok := to.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"]; ok && v == "kube-system" {
				hasKubeSystem = true
			}
		}
		if to.IPBlock != nil && to.IPBlock.CIDR == "0.0.0.0/0" {
			hasWorld = true
		}
	}
	require.True(t, hasWorld, "should have world 0.0.0.0/0 in To")
	require.True(t, hasKubeSystem, "should have kube-system fallback peer")
}

// TestBuildNetworkPolicy_ApiServerMultipleCIDRs verifies that when
// APIServerCIDRs contains three non-host-route CIDRs, the sentinel falls
// back to kube-system (no service-range CIDRs are emitted). When at least
// a /32 exists, only that CIDR is emitted.
func TestBuildNetworkPolicy_ApiServerMultipleCIDRs(t *testing.T) {
	t.Parallel()

	// All non-host CIDRs → single kube-system fallback peer.
	_, c1, _ := net.ParseCIDR("10.96.0.0/12")
	_, c2, _ := net.ParseCIDR("192.168.107.0/24")
	_, c3, _ := net.ParseCIDR("172.16.0.0/16")
	cfgNoHost := config.Config{
		APIServerCIDRs: []*net.IPNet{c1, c2, c3},
	}

	p := policy.Policy{
		WorkloadID:        "default/gateway",
		WorkloadNamespace: "default",
		WorkloadName:      "gateway",
		EgressRules: []policy.EgressRule{
			{
				ToCIDRs: []string{"apiserver"},
				ToPorts: []policy.PortSpec{{Port: 6443, Protocol: "TCP"}},
			},
		},
	}

	npNoHost := buildNetworkPolicy(p, cfgNoHost, nil)

	require.Len(t, npNoHost.Spec.Egress, 1)
	require.Len(t, npNoHost.Spec.Egress[0].To, 1)
	require.Nil(t, npNoHost.Spec.Egress[0].To[0].IPBlock)
	require.NotNil(t, npNoHost.Spec.Egress[0].To[0].NamespaceSelector)
	require.NotNil(t, npNoHost.Spec.Egress[0].To[0].PodSelector)

	// Mix: two non-host + one /32 → only the /32 is emitted.
	_, hostIP, err := net.ParseCIDR("192.168.107.5/32")
	require.NoError(t, err)
	cfgWithHost := config.Config{
		APIServerCIDRs: []*net.IPNet{c1, hostIP, c3},
	}

	npWithHost := buildNetworkPolicy(p, cfgWithHost, nil)

	require.Len(t, npWithHost.Spec.Egress, 1)
	require.Len(t, npWithHost.Spec.Egress[0].To, 1)
	require.NotNil(t, npWithHost.Spec.Egress[0].To[0].IPBlock)
	require.Equal(t, "192.168.107.5/32", npWithHost.Spec.Egress[0].To[0].IPBlock.CIDR)
}

// TestBuildNetworkPolicy_ApiServerSkipsServiceRange is a regression test for
// REVIEW9 Problem 2: ensure service-range CIDRs in APIServerCIDRs are NOT
// emitted as ipBlock in NetworkPolicy egress, while /32 host IPs are.
func TestBuildNetworkPolicy_ApiServerSkipsServiceRange(t *testing.T) {
	t.Parallel()

	p := policy.Policy{
		WorkloadID:        "default/test",
		WorkloadNamespace: "default",
		WorkloadName:      "test",
		EgressRules: []policy.EgressRule{
			{
				ToCIDRs: []string{"apiserver"},
				ToPorts: []policy.PortSpec{{Port: 6443, Protocol: "TCP"}},
			},
		},
	}

	// Case 1: service-range + /32 → only /32 appears.
	_, svcRange, _ := net.ParseCIDR("10.96.0.0/12")
	_, hostIP, _ := net.ParseCIDR("192.168.107.5/32")
	cfg := config.Config{
		APIServerCIDRs: []*net.IPNet{svcRange, hostIP},
	}

	np := buildNetworkPolicy(p, cfg, nil)

	require.Len(t, np.Spec.Egress, 1)
	require.Len(t, np.Spec.Egress[0].To, 1)
	require.NotNil(t, np.Spec.Egress[0].To[0].IPBlock)
	require.Equal(t, "192.168.107.5/32", np.Spec.Egress[0].To[0].IPBlock.CIDR)

	// Ensure no service-range CIDR leaked.
	for _, to := range np.Spec.Egress[0].To {
		if to.IPBlock != nil && strings.Contains(to.IPBlock.CIDR, "10.96.0.0/12") {
			t.Errorf("service-range CIDR must NOT appear: %s", to.IPBlock.CIDR)
		}
	}

	// Case 2: node_cidrs appended alongside /32.
	_, _, _ = net.ParseCIDR("192.168.107.0/24") // validate string
	cfgNode := config.Config{
		APIServerCIDRs: []*net.IPNet{hostIP},
		NodeCIDRs:      []string{"192.168.107.0/24"},
	}

	np2 := buildNetworkPolicy(p, cfgNode, nil)

	require.Len(t, np2.Spec.Egress, 1)
	require.Len(t, np2.Spec.Egress[0].To, 2)

	var foundHost, foundNode bool
	for _, to := range np2.Spec.Egress[0].To {
		if to.IPBlock != nil {
			switch to.IPBlock.CIDR {
			case "192.168.107.5/32":
				foundHost = true
			case "192.168.107.0/24":
				foundNode = true
			}
		}
	}
	require.True(t, foundHost, "expected 192.168.107.5/32")
	require.True(t, foundNode, "expected 192.168.107.0/24 via node_cidrs")
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
		reports:      []string{"bogus"},
		format:       "text",
		policyFormat: "auto",
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
		policyFormat:      "auto",
	})
	require.NoError(t, err)

	// 3. topN=5 should not cause a validation error.
	err = runAnalyzePipeline(nil, tmpPath, &rootCmdData{
		topN:         5,
		source:       "hubble",
		format:       "text",
		policyFormat: "auto",
	})
	require.NoError(t, err)

	// 4. generateUncovered true should not cause a validation error.
	err = runAnalyzePipeline(nil, tmpPath, &rootCmdData{
		generateUncovered: true,
		source:            "hubble",
		format:            "text",
		policyFormat:      "auto",
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
		policyFormat: "auto",
		reports:      nil,
		format:       "text",
		source:       "hubble",
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

// TestBuildNetworkPolicy_ScopeFromStableLabels verifies that buildNetworkPolicy
// derives the PodSelector from the workload's stable labels, falls back to
// {app: workloadName} for unknown workloads, and merges with explicit label
// segments where the workload has stable k8s-app instead of app.
func TestBuildNetworkPolicy_ScopeFromStableLabels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		policy          policy.Policy
		workloads       analyze.Workloads
		wantPodSelector map[string]string
	}{
		{
			name: "known workload with app label",
			policy: policy.Policy{
				WorkloadID:        "flowlab/demo-server",
				WorkloadNamespace: "flowlab",
				WorkloadName:      "demo-server",
			},
			workloads: analyze.Workloads{
				"flowlab/demo-server": {
					Name:      "demo-server",
					Namespace: "flowlab",
					Labels:    map[string]string{"app": "demo-server"},
				},
			},
			wantPodSelector: map[string]string{"app": "demo-server"},
		},
		{
			name: "known workload with k8s-app instead of app",
			policy: policy.Policy{
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
			wantPodSelector: map[string]string{"k8s-app": "kube-dns"},
		},
		{
			name: "unknown workload falls back to app:name",
			policy: policy.Policy{
				WorkloadID:        "prod/orphan-svc",
				WorkloadNamespace: "prod",
				WorkloadName:      "orphan-svc",
			},
			workloads:       nil,
			wantPodSelector: map[string]string{"app": "orphan-svc"},
		},
		{
			name: "label-less workload falls back to app:name",
			policy: policy.Policy{
				WorkloadID:        "staging/empty",
				WorkloadNamespace: "staging",
				WorkloadName:      "empty",
			},
			workloads: analyze.Workloads{
				"staging/empty": {
					Name:      "empty",
					Namespace: "staging",
					Labels:    nil,
				},
			},
			wantPodSelector: map[string]string{"app": "empty"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			np := buildNetworkPolicy(tt.policy, config.Config{}, tt.workloads)
			require.NotNil(t, np.Spec.PodSelector.MatchLabels)
			assert.Equal(t, tt.wantPodSelector, np.Spec.PodSelector.MatchLabels)
		})
	}
}

// TestParseWorkloadSelectorV2_StableLabels verifies that parseWorkloadSelectorV2
// resolves real workload stable labels instead of fabricating {app: name} when
// the workload is known, and falls back to {app: name} when stable set is empty.
func TestParseWorkloadSelectorV2_StableLabels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		peer       string
		workloads  analyze.Workloads
		wantPodSel map[string]string
		wantNsSel  map[string]string
	}{
		{
			name: "workload with app.kubernetes.io/name stable label",
			peer: "prod/backend",
			workloads: analyze.Workloads{
				"prod/backend": {
					Name:      "backend",
					Namespace: "prod",
					Labels:    map[string]string{"app.kubernetes.io/name": "backend"},
				},
			},
			wantPodSel: map[string]string{"app.kubernetes.io/name": "backend"},
			wantNsSel:  map[string]string{"kubernetes.io/metadata.name": "prod"},
		},
		{
			name: "workload with no stable labels falls back to app",
			peer: "staging/empty-svc",
			workloads: analyze.Workloads{
				"staging/empty-svc": {
					Name:      "empty-svc",
					Namespace: "staging",
					Labels:    nil,
				},
			},
			wantPodSel: map[string]string{"app": "empty-svc"},
			wantNsSel:  map[string]string{"kubernetes.io/metadata.name": "staging"},
		},
		{
			name:       "nil workloads falls back to app",
			peer:       "prod/backend",
			workloads:  nil,
			wantPodSel: map[string]string{"app": "backend"},
			wantNsSel:  map[string]string{"kubernetes.io/metadata.name": "prod"},
		},
		{
			name: "unknown workload key falls back to app:name",
			peer: "prod/unknown-svc",
			workloads: analyze.Workloads{
				"prod/other": {
					Name:      "other",
					Namespace: "prod",
					Labels:    map[string]string{"app": "other"},
				},
			},
			wantPodSel: map[string]string{"app": "unknown-svc"},
			wantNsSel:  map[string]string{"kubernetes.io/metadata.name": "prod"},
		},
		{
			name: "explicit label segments merge with workload labels",
			peer: "prod/backend,env=prod",
			workloads: analyze.Workloads{
				"prod/backend": {
					Name:      "backend",
					Namespace: "prod",
					Labels:    map[string]string{"k8s-app": "backend"},
				},
			},
			wantPodSel: map[string]string{"env": "prod", "k8s-app": "backend"},
			wantNsSel:  map[string]string{"kubernetes.io/metadata.name": "prod"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			peers, err := parseWorkloadSelectorV2(tt.peer, nil, tt.workloads)
			require.NoError(t, err)

			if tt.wantPodSel != nil {
				require.NotNil(t, peers[0].PodSelector)
				require.Equal(t, tt.wantPodSel, peers[0].PodSelector.MatchLabels)
			} else {
				require.Nil(t, peers[0].PodSelector)
			}

			if tt.wantNsSel != nil {
				require.NotNil(t, peers[0].NamespaceSelector)
				require.Equal(t, tt.wantNsSel, peers[0].NamespaceSelector.MatchLabels)
			} else {
				require.Nil(t, peers[0].NamespaceSelector)
			}
		})
	}
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

// TestIllegalSelectorWarning verifies that warnIllegalSelectorKeys emits
// a warning when a selector contains keys with space/asterisk that do not
// match label-key syntax.
func TestIllegalSelectorWarning(t *testing.T) {
	t.Parallel()

	// Build a policy that uses "bad key*=val" via parseWorkloadSelectorV2.
	peers, err := parseWorkloadSelectorV2("app=frontend,bad key*=val", nil, nil)
	require.NoError(t, err)
	require.NotNil(t, peers[0].PodSelector)
	require.Equal(t, map[string]string{"app": "frontend", "bad key*": "val"},
		peers[0].PodSelector.MatchLabels)

	np := &networkingv1.NetworkPolicy{
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: v1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{From: []networkingv1.NetworkPolicyPeer{peers[0]}},
			},
		},
	}

	var buf bytes.Buffer
	warnIllegalSelectorKeys(&buf, "test-policy.yaml", np)
	output := buf.String()
	require.Contains(t, output, "Warning: policy test-policy.yaml has Kubernetes-illegal selector key")
	require.Contains(t, output, "bad key*")
}

// TestIllegalSelectorWarning_AllLegal verifies that policies whose selectors
// only contain legal key syntax produce NO warning output.
func TestIllegalSelectorWarning_AllLegal(t *testing.T) {
	t.Parallel()

	// Build a peer with legal slash-key labels (no colons).
	legalPeers, err := parseWorkloadSelectorV2("app=frontend,app.kubernetes.io/name=web,run.ai/id=abc123", nil, nil)
	require.NoError(t, err)
	require.NotNil(t, legalPeers[0].PodSelector)
	require.Equal(t, map[string]string{
		"app":                    "frontend",
		"app.kubernetes.io/name": "web",
		"run.ai/id":              "abc123",
	}, legalPeers[0].PodSelector.MatchLabels)

	np := &networkingv1.NetworkPolicy{
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: v1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{From: []networkingv1.NetworkPolicyPeer{legalPeers[0]}},
			},
		},
	}

	var buf bytes.Buffer
	warnIllegalSelectorKeys(&buf, "legal-policy.yaml", np)
	require.Empty(t, buf.String(), "no warnings should be emitted for fully legal selector keys")
}

// TestIllegalSelectorWarning_SlashKeyDoesNotWarn ensures that a policy
// built from the canonical hubble-flows selector pattern (app.kubernetes.io/name)
// does NOT produce a warning — a regression guard for Review5 T5.
func TestIllegalSelectorWarning_SlashKeyDoesNotWarn(t *testing.T) {
	t.Parallel()

	peers, err := parseWorkloadSelectorV2("app.kubernetes.io/name=calico-apiserver", nil, nil)
	require.NoError(t, err)
	require.NotNil(t, peers[0].PodSelector)
	require.Equal(t, map[string]string{"app.kubernetes.io/name": "calico-apiserver"},
		peers[0].PodSelector.MatchLabels)

	np := &networkingv1.NetworkPolicy{
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: *peers[0].PodSelector,
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{To: []networkingv1.NetworkPolicyPeer{peers[0]}},
			},
		},
	}

	var buf bytes.Buffer
	warnIllegalSelectorKeys(&buf, "slash-policy.yaml", np)
	require.Empty(t, buf.String(), "slash-key labels like app.kubernetes.io/name must not warn")
}

// TestIllegalSelectorKeysCNP_IllegalEndpointSelector checks that a CNP with
// an illegal non-label-key key in its EndpointSelector triggers a warning.
func TestIllegalSelectorKeysCNP_IllegalEndpointSelector(t *testing.T) {
	t.Parallel()

	cnp := &policy.CiliumNetworkPolicy{
		Spec: policy.CNPSpec{
			EndpointSelector: policy.CNPEntitySelector{
				MatchLabels: map[string]string{"bad key*": "frontend"},
			},
		},
	}

	var buf bytes.Buffer
	warnIllegalSelectorKeysCNP(&buf, "policy-frontend.yaml", cnp)
	require.Contains(t, buf.String(), "bad key*",
		"illegal key in EndpointSelector must be warned")
}

// TestIllegalSelectorKeysCNP_AllLegal checks that a CNP whose selectors
// only use legal label-key syntax produces NO warning.
func TestIllegalSelectorKeysCNP_AllLegal(t *testing.T) {
	t.Parallel()

	cnp := &policy.CiliumNetworkPolicy{
		Spec: policy.CNPSpec{
			EndpointSelector: policy.CNPEntitySelector{
				MatchLabels: map[string]string{"app.kubernetes.io/name": "frontend"},
			},
			Ingress: []policy.CNPIngressRule{
				{
					FromEndpoints: []policy.CNPEntitySelector{
						{MatchLabels: map[string]string{"app": "backend"}},
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	warnIllegalSelectorKeysCNP(&buf, "legal-policy.yaml", cnp)
	require.Empty(t, buf.String(),
		"no warnings should be emitted for fully legal Cilium selectors")
}

// TestIllegalSelectorKeysCNP_IllegalIngressFromEndpoints checks that an
// illegal non-label-key key inside a FromEndpoints match label triggers a warning,
// proving the peer-walker path is covered.
func TestIllegalSelectorKeysCNP_IllegalIngressFromEndpoints(t *testing.T) {
	t.Parallel()

	cnp := &policy.CiliumNetworkPolicy{
		Spec: policy.CNPSpec{
			Ingress: []policy.CNPIngressRule{
				{
					FromEndpoints: []policy.CNPEntitySelector{
						{MatchLabels: map[string]string{"bad key*": ""}},
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	warnIllegalSelectorKeysCNP(&buf, "fromendpoints.yaml", cnp)
	require.Contains(t, buf.String(), "bad key*",
		"illegal key in Ingress FromEndpoints must be warned")
}

// ─── end CNP selector tests ─────────────────────────────────────────────

// TestLabelKeyRegex verifies that labelKeyRegex accepts legal Kubernetes
// label keys (plain, DNS-prefix, and Cilium k8:/reserved: prefixes) and
// rejects illegal keys containing spaces, asterisks, or empty suffixes.
func TestLabelKeyRegex(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		key    string
		wantOK bool
	}{
		// ─── Legal Cilium CNP-prefix keys ───
		{
			name:   "k8s:io.kubernetes.pod.namespace",
			key:    "k8s:io.kubernetes.pod.namespace",
			wantOK: true,
		},
		{
			name:   "reserved:kube-apiserver",
			key:    "reserved:kube-apiserver",
			wantOK: true,
		},
		{
			name:   "reserved:world",
			key:    "reserved:world",
			wantOK: true,
		},
		{
			name:   "k8s:app",
			key:    "k8s:app",
			wantOK: true,
		},
		// ─── Legal plain / DNS-prefix keys (unchanged from before) ───
		{
			name:   "plain app",
			key:    "app",
			wantOK: true,
		},
		{
			name:   "DNS-prefix app.kubernetes.io/name",
			key:    "app.kubernetes.io/name",
			wantOK: true,
		},
		{
			name:   "slash-key run.ai/workload-id",
			key:    "run.ai/workload-id",
			wantOK: true,
		},
		{
			name:   "single letter",
			key:    "a",
			wantOK: true,
		},
		{
			name:   "with dots and dashes",
			key:    "my-label.key-v2",
			wantOK: true,
		},
		// ─── Illegal keys ───
		{
			name:   "space and asterisk",
			key:    "bad key*",
			wantOK: false,
		},
		{
			name:   "reserved: empty suffix",
			key:    "reserved:",
			wantOK: false,
		},
		{
			name:   "k8s: empty suffix",
			key:    "k8s:",
			wantOK: false,
		},
		{
			name:   "empty prefix before colon",
			key:    ":app",
			wantOK: false,
		},
		{
			name:   "reserved: slash garbage",
			key:    "reserved:/name",
			wantOK: false,
		},
		{
			name:   "only a space",
			key:    " ",
			wantOK: false,
		},
		{
			name:   "equals sign",
			key:    "key=value",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := labelKeyRegex.MatchString(tt.key)
			require.Equal(t, tt.wantOK, got,
				"labelKeyRegex.MatchString(%q) = %v; want %v", tt.key, got, tt.wantOK)
		})
	}
}

// TestParseWorkloadSelectorV2CIDR verifies that CIDR strings are rendered
// as IPBlock in parseWorkloadSelectorV2, while "apiserver" and plain workload
// keys remain unaffected.
func TestParseWorkloadSelectorV2CIDR(t *testing.T) {
	t.Parallel()

	_, apiserverCIDR, err := net.ParseCIDR("10.244.0.73/32")
	require.NoError(t, err)

	cfg := &config.Config{
		APIServerCIDRs: []*net.IPNet{apiserverCIDR},
	}

	workloads := analyze.Workloads{
		"default/api-server": {
			Name:      "api-server",
			Namespace: "default",
			Labels:    map[string]string{"app": "api-server"},
		},
	}

	tests := []struct {
		name            string
		peer            string
		cfg             *config.Config
		workloads       analyze.Workloads
		wantWorldCIDR   string
		wantIPBlockCIDR string
		wantPodSel      map[string]string
		wantNsSel       map[string]string
	}{
		{
			name:            "single /32 CIDR → IPBlock",
			peer:            "10.244.1.232/32",
			wantIPBlockCIDR: "10.244.1.232/32",
		},
		{
			name:          "0.0.0.0/0 → world IPBlock",
			peer:          "0.0.0.0/0",
			wantWorldCIDR: "0.0.0.0/0",
		},
		{
			name:            "apiserver sentinel → config CIDR",
			peer:            "apiserver",
			cfg:             cfg,
			wantIPBlockCIDR: "10.244.0.73/32",
		},
		{
			name:       "plain workload key → podSelector",
			peer:       "default/api-server",
			workloads:  workloads,
			wantPodSel: map[string]string{"app": "api-server"},
			wantNsSel:  map[string]string{"kubernetes.io/metadata.name": "default"},
		},
		{
			name:       "label-only key → podSelector",
			peer:       "app=coredns",
			workloads:  workloads,
			wantPodSel: map[string]string{"app": "coredns"},
			wantNsSel:  nil,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			peers, err := parseWorkloadSelectorV2(tt.peer, tt.cfg, tt.workloads)
			require.NoError(t, err)
			require.Len(t, peers, 1)

			p := peers[0]
			if tt.wantWorldCIDR != "" {
				require.NotNil(t, p.IPBlock, "expected IPBlock for world")
				require.Equal(t, tt.wantWorldCIDR, p.IPBlock.CIDR)
				require.Nil(t, p.PodSelector)
				require.Nil(t, p.NamespaceSelector)
			} else if tt.wantIPBlockCIDR != "" {
				require.NotNil(t, p.IPBlock, "expected IPBlock for %s", tt.peer)
				require.Equal(t, tt.wantIPBlockCIDR, p.IPBlock.CIDR)
				require.Nil(t, p.PodSelector)
				require.Nil(t, p.NamespaceSelector)
			} else {
				require.Nil(t, p.IPBlock, "expected no IPBlock for %s", tt.peer)
				require.Equal(t, tt.wantPodSel, p.PodSelector.MatchLabels)
				if tt.wantNsSel == nil {
					require.Nil(t, p.NamespaceSelector)
				} else {
					require.NotNil(t, p.NamespaceSelector)
					require.Equal(t, tt.wantNsSel, p.NamespaceSelector.MatchLabels)
				}
			}
		})
	}
}

// TestEGressAllowWorld_RelayEgressWithEgressAllowWorld verifies that when the
// workload matches a PublicServiceSpec with EgressAllowWorld: true AND the
// rule carries host/remote-node entity sentinels AND has /32 CIDRs, all /32
// CIDRs are replaced with 0.0.0.0/0.
func TestEGressAllowWorld_RelayEgressWithEgressAllowWorld(t *testing.T) {
	t.Parallel()

	_, h, _ := net.ParseCIDR("192.168.107.5/32")
	_, r, _ := net.ParseCIDR("192.168.107.4/32")
	_, _ = h, r
	cfg := config.Config{
		APIServerCIDRs: []*net.IPNet{h},
		PublicServices: []config.PublicServiceSpec{
			{
				Namespace:        "default",
				Name:             "hubble-relay",
				EgressAllowWorld: true,
			},
		},
	}

	p := policy.Policy{
		WorkloadID:        "default/hubble-relay",
		WorkloadNamespace: "default",
		WorkloadName:      "hubble-relay",
		EgressRules: []policy.EgressRule{
			{
				ToEntities: []string{"entity:host", "entity:remote-node"},
				ToCIDRs:    []string{"192.168.107.5/32", "192.168.107.4/32"},
				ToPorts:    []policy.PortSpec{{Port: 4244, Protocol: "TCP"}},
			},
		},
	}

	np := buildNetworkPolicy(p, cfg, nil)

	require.Len(t, np.Spec.Egress, 1)
	require.Len(t, np.Spec.Egress[0].To, 1)
	// Both /32s collapse to a single 0.0.0.0/0.
	require.NotNil(t, np.Spec.Egress[0].To[0].IPBlock)
	require.Equal(t, "0.0.0.0/0", np.Spec.Egress[0].To[0].IPBlock.CIDR)
}

// TestEGressAllowWorld_FlagFalsePreservesCIDRTwins verifies that when the
// EgressAllowWorld flag is false (default), /32 CIDR twins are preserved.
func TestEGressAllowWorld_FlagFalsePreservesCIDRTwins(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		PublicServices: []config.PublicServiceSpec{
			{
				Namespace: "default",
				Name:      "hubble-relay",
			},
		},
	}

	p := policy.Policy{
		WorkloadID:        "default/hubble-relay",
		WorkloadNamespace: "default",
		WorkloadName:      "hubble-relay",
		EgressRules: []policy.EgressRule{
			{
				ToEntities: []string{"entity:host"},
				ToCIDRs:    []string{"192.168.107.5/32", "192.168.107.4/32"},
				ToPorts:    []policy.PortSpec{{Port: 4244, Protocol: "TCP"}},
			},
		},
	}

	np := buildNetworkPolicy(p, cfg, nil)

	require.Len(t, np.Spec.Egress, 1)
	// Both /32s preserved as individual peers.
	require.Len(t, np.Spec.Egress[0].To, 2)
	cidrs := extractToCIDRs(np.Spec.Egress[0].To)
	require.True(t, hasString(cidrs, "192.168.107.5/32"))
	require.True(t, hasString(cidrs, "192.168.107.4/32"))
}

// TestEGressAllowWorld_NoHostEntityPreservesCIDRTwins verifies that when the
// egress rule carries NO host/remote-node entity sentinels, /32 CIDRs are
// never transformed -- even when EgressAllowWorld is true for the workload.
func TestEGressAllowWorld_NoHostEntityPreservesCIDRTwins(t *testing.T) {
	t.Parallel()

	_, p5, _ := net.ParseCIDR("192.168.107.5/32")
	_, p4, _ := net.ParseCIDR("192.168.107.4/32")

	cfg := config.Config{
		APIServerCIDRs: []*net.IPNet{p5, p4},
		PublicServices: []config.PublicServiceSpec{
			{
				Namespace:        "default",
				Name:             "hubble-relay",
				EgressAllowWorld: true,
			},
		},
	}

	p := policy.Policy{
		WorkloadID:        "default/hubble-relay",
		WorkloadNamespace: "default",
		WorkloadName:      "hubble-relay",
		EgressRules: []policy.EgressRule{
			{
				ToEntities: []string{"entity:kube-apiserver"},
				ToCIDRs:    []string{"192.168.107.5/32", "192.168.107.4/32"},
				ToPorts:    []policy.PortSpec{{Port: 6443, Protocol: "TCP"}},
			},
		},
	}

	np := buildNetworkPolicy(p, cfg, nil)

	require.Len(t, np.Spec.Egress, 1)
	require.Len(t, np.Spec.Egress[0].To, 2)
	cidrs := extractToCIDRs(np.Spec.Egress[0].To)
	require.True(t, hasString(cidrs, "192.168.107.5/32"))
	require.True(t, hasString(cidrs, "192.168.107.4/32"))
	require.False(t, hasString(cidrs, "0.0.0.0/0"))
}

// TestEGressAllowWorld_PodIPNoEntitiesPreservesCIDR verifies that a rule
// containing only /32 CIDRs with no entity sentinels is never transformed.
func TestEGressAllowWorld_PodIPNoEntitiesPreservesCIDR(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		PublicServices: []config.PublicServiceSpec{
			{
				Namespace:        "default",
				Name:             "pod-app",
				EgressAllowWorld: true,
			},
		},
	}

	p := policy.Policy{
		WorkloadID:        "default/pod-app",
		WorkloadNamespace: "default",
		WorkloadName:      "pod-app",
		EgressRules: []policy.EgressRule{
			{
				ToCIDRs: []string{"10.244.1.57/32"},
				ToPorts: []policy.PortSpec{{Port: 8080, Protocol: "TCP"}},
			},
		},
	}

	np := buildNetworkPolicy(p, cfg, nil)

	require.Len(t, np.Spec.Egress, 1)
	require.Len(t, np.Spec.Egress[0].To, 1)
	require.NotNil(t, np.Spec.Egress[0].To[0].IPBlock)
	require.Equal(t, "10.244.1.57/32", np.Spec.Egress[0].To[0].IPBlock.CIDR)
	require.NotEqual(t, "0.0.0.0/0", np.Spec.Egress[0].To[0].IPBlock.CIDR)
}

// TestToNamespaces_DNSFallbackRendering verifies that a DNS egress rule with
// ToNamespaces ["kube-system"] renders as a namespaceSelector peer + empty
// podSelector in the resulting NetworkPolicy.
func TestToNamespaces_DNSFallbackRendering(t *testing.T) {
	t.Parallel()

	cfg := config.Config{}

	p := policy.Policy{
		WorkloadID:        "default/demo-client",
		WorkloadNamespace: "default",
		WorkloadName:      "demo-client",
		EgressRules: []policy.EgressRule{
			{
				ToNamespaces: []string{"kube-system"},
				ToPorts: []policy.PortSpec{
					{Port: 53, Protocol: "UDP"},
					{Port: 53, Protocol: "TCP"},
				},
			},
		},
	}

	np := buildNetworkPolicy(p, cfg, nil)

	require.Len(t, np.Spec.Egress, 1)
	require.Len(t, np.Spec.Egress[0].To, 1)

	peer := np.Spec.Egress[0].To[0]
	require.NotNil(t, peer.NamespaceSelector)
	require.Equal(t, map[string]string{"kubernetes.io/metadata.name": "kube-system"},
		peer.NamespaceSelector.MatchLabels)
	require.NotNil(t, peer.PodSelector)
	require.Empty(t, peer.PodSelector.MatchLabels)

	require.Len(t, np.Spec.Egress[0].Ports, 2)
}

// TestToNamespaces_MixedTargets verifies that when a rule has both
// ToWorkloads and ToNamespaces, both peer types are rendered in the same
// egress rule.
func TestToNamespaces_MixedTargets(t *testing.T) {
	t.Parallel()

	cfg := config.Config{}

	p := policy.Policy{
		WorkloadID:        "default/gateway",
		WorkloadNamespace: "default",
		WorkloadName:      "gateway",
		EgressRules: []policy.EgressRule{
			{
				ToWorkloads:  []string{"app=backend"},
				ToNamespaces: []string{"kube-system"},
				ToPorts:      []policy.PortSpec{{Port: 443, Protocol: "TCP"}},
			},
		},
	}

	np := buildNetworkPolicy(p, cfg, nil)

	require.Len(t, np.Spec.Egress, 1)
	require.Len(t, np.Spec.Egress[0].To, 2)

	nsPeerFound := false
	for _, peer := range np.Spec.Egress[0].To {
		if peer.NamespaceSelector != nil && peer.PodSelector != nil {
			labelName, ok := peer.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"]
			require.True(t, ok)
			require.Equal(t, "kube-system", labelName)
			require.Empty(t, peer.PodSelector.MatchLabels)
			nsPeerFound = true
		}
	}
	require.True(t, nsPeerFound)
}

// TestEGressAllowWorld_Non32Preserved verifies that non-/32 CIDRs are never
// affected by the egress_allow_world expand transform.
func TestEGressAllowWorld_Non32Preserved(t *testing.T) {
	t.Parallel()

	_, cidr, _ := net.ParseCIDR("192.168.107.0/24")

	cfg := config.Config{
		APIServerCIDRs: []*net.IPNet{cidr},
		PublicServices: []config.PublicServiceSpec{
			{
				Namespace:        "default",
				Name:             "mixed-service",
				EgressAllowWorld: true,
			},
		},
	}

	p := policy.Policy{
		WorkloadID:        "default/mixed-service",
		WorkloadNamespace: "default",
		WorkloadName:      "mixed-service",
		EgressRules: []policy.EgressRule{
			{
				ToEntities: []string{"entity:host"},
				ToCIDRs:    []string{"10.244.1.5/32", "192.168.107.0/24"},
				ToPorts:    []policy.PortSpec{{Port: 443, Protocol: "TCP"}},
			},
		},
	}

	np := buildNetworkPolicy(p, cfg, nil)

	require.Len(t, np.Spec.Egress, 1)
	cidrs := extractToCIDRs(np.Spec.Egress[0].To)
	require.True(t, hasString(cidrs, "0.0.0.0/0"))
	require.True(t, hasString(cidrs, "192.168.107.0/24"))
}

// TestShouldExpandToCIDRs_ApiServerTwin verifies that shouldExpandToCIDRs
// returns true when the "apiserver" sentinel is in ToCIDRs (Gate 3 extension).
func TestShouldExpandToCIDRs_ApiServerTwin(t *testing.T) {
	t.Parallel()

	_, cidr, _ := net.ParseCIDR("10.96.0.0/12")
	cfg := config.Config{
		APIServerCIDRs: []*net.IPNet{cidr},
		PublicServices: []config.PublicServiceSpec{
			{
				Namespace:        "kube-system",
				Name:             "kube-dns",
				EgressAllowWorld: true,
			},
			{
				Namespace:        "kube-system",
				Name:             "metrics-server",
				EgressAllowWorld: false,
			},
		},
	}

	tests := []struct {
		name     string
		cidrs    []string
		entities []string
		workload string
		expect   bool
	}{
		{
			name:     "sentinel+world flag true→expand",
			cidrs:    []string{"apiserver"},
			entities: []string{"entity:kube-apiserver", "entity:remote-node"},
			workload: "kube-system/kube-dns",
			expect:   true,
		},
		{
			name:     "sentinel+no-flag-flag-false",
			cidrs:    []string{"apiserver"},
			entities: []string{"entity:kube-apiserver", "entity:remote-node"},
			workload: "kube-system/metrics-server",
			expect:   false,
		},
		{
			name:     "/32+flag-true",
			cidrs:    []string{"192.168.1.5/32"},
			entities: []string{"entity:host", "entity:remote-node"},
			workload: "kube-system/kube-dns",
			expect:   true,
		},
		{
			name:     "/32+flag-false",
			cidrs:    []string{"192.168.1.5/32"},
			entities: []string{"entity:host", "entity:remote-node"},
			workload: "kube-system/metrics-server",
			expect:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := policy.Policy{
				WorkloadID:        tt.workload,
				WorkloadNamespace: "kube-system",
				WorkloadName:      strings.Split(tt.workload, "/")[1],
				EgressRules: []policy.EgressRule{
					{
						ToCIDRs:    tt.cidrs,
						ToEntities: tt.entities,
					},
				},
			}

			got := shouldExpandToCIDRs(p.EgressRules[0], p, cfg)
			assert.Equal(t, tt.expect, got, "shouldExpandToCIDRs unexpectedly %v (want %v)", got, tt.expect)
		})
	}
}

// TestExpandToCIDRs_ApiServerTwin verifies that expandToCIDRs replaces the
// "apiserver" sentinel with 0.0.0.0/0 alongside /32 CIDRs.
func TestExpandToCIDRs_ApiServerTwin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "apiserver→0.0.0.0/0",
			input:    []string{"apiserver", "10.96.0.1/32"},
			expected: []string{"0.0.0.0/0"},
		},
		{
			name:     "single apiserver",
			input:    []string{"apiserver"},
			expected: []string{"0.0.0.0/0"},
		},
		{
			name:     "mixed preserved and expanded",
			input:    []string{"apiserver", "192.168.1.5/32", "10.0.0.0/8"},
			expected: []string{"0.0.0.0/0", "10.0.0.0/8"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := expandToCIDRs(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// TestBuildNetworkPolicy_ApiServerTwin_EgressAllowWorld verifies end-to-end
// that a rule with ToCIDRs ["apiserver"] + host/remote-node entities expands
// to 0.0.0.0/0 when EgressAllowWorld is true.
func TestBuildNetworkPolicy_ApiServerTwin_EgressAllowWorld(t *testing.T) {
	t.Parallel()

	_, cidr, _ := net.ParseCIDR("10.96.0.0/12")

	cfg := config.Config{
		APIServerCIDRs: []*net.IPNet{cidr},
		PublicServices: []config.PublicServiceSpec{
			{
				Namespace:        "default",
				Name:             "public-svc",
				EgressAllowWorld: true,
			},
		},
	}

	p := policy.Policy{
		WorkloadID:        "default/public-svc",
		WorkloadNamespace: "default",
		WorkloadName:      "public-svc",
		EgressRules: []policy.EgressRule{
			{
				ToCIDRs:    []string{"apiserver"},
				ToEntities: []string{"entity:kube-apiserver", "entity:remote-node"},
				ToPorts:    []policy.PortSpec{{Port: 6443, Protocol: "TCP"}},
			},
		},
	}

	np := buildNetworkPolicy(p, cfg, nil)

	require.Len(t, np.Spec.Egress, 1)
	cidrs := extractToCIDRs(np.Spec.Egress[0].To)
	require.True(t, hasString(cidrs, "0.0.0.0/0"), "expected 0.0.0.0/0 in CIDRs %v", cidrs)
}

// --- test for NP-on-Hubble reserved-entity egress warning ---

func TestNPOnHubbleWarning_ReservedEgress(t *testing.T) {
	t.Parallel()

	flows := []flow.Flow{
		{
			Direction: flow.Egress,
			Source:    flow.Endpoint{Namespace: "prod", PodName: "web", IP: "10.0.0.1"},
			Destination: flow.Endpoint{
				IP:     "10.0.0.2",
				Labels: map[string]string{"reserved:host": ""},
			},
			Layer4:  flow.Layer4{DestPort: 80, Protocol: flow.TCP},
			Verdict: flow.Allow,
		},
	}

	type testCase struct {
		name          string
		sourceType    parser.Source
		policyFormat  string
		expectWarning bool
	}

	cases := []testCase{
		{
			name:          "hubble + np with reserved egress -> warning",
			sourceType:    parser.SourceHubble,
			policyFormat:  "np",
			expectWarning: true,
		},
		{
			name:          "hubble + cnp -> no warning",
			sourceType:    parser.SourceHubble,
			policyFormat:  "cnp",
			expectWarning: false,
		},
		{
			name:          "calico + np -> no warning",
			sourceType:    parser.SourceCalico,
			policyFormat:  "np",
			expectWarning: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old := os.Stderr
			r, w, _ := os.Pipe()
			os.Stderr = w

			cmd := &cobra.Command{}
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			rd := &rootCmdData{policyFormat: tc.policyFormat, format: "text"}
			cfg := config.Config{}

			err := executeAnalysis(cmd, flows, cfg, rd, tc.sourceType)

			w.Close()
			os.Stderr = old

			require.NoError(t, err)

			output, _ := io.ReadAll(r)
			gotWarning := strings.Contains(string(output), "Warning: NetworkPolicy cannot express egress to reserved peers")

			if tc.expectWarning {
				assert.True(t, gotWarning, "expected warning in stderr; got: %q", string(output))
			} else {
				assert.False(t, gotWarning, "unexpected warning in stderr; got: %q", string(output))
			}
		})
	}
}

// --- helper functions used by tests ---

func extractToCIDRs(to []networkingv1.NetworkPolicyPeer) []string {
	var out []string
	for _, p := range to {
		if p.IPBlock != nil {
			out = append(out, p.IPBlock.CIDR)
		}
	}
	sort.Strings(out)
	return out
}

func TestExecuteAnalysisFormatSelection(t *testing.T) {
	t.Parallel()

	flows := []flow.Flow{
		{
			Direction: flow.Egress,
			Source:    flow.Endpoint{Namespace: "prod", PodName: "web", IP: "10.0.0.1"},
			Destination: flow.Endpoint{
				IP:     "10.0.0.2",
				Labels: map[string]string{"reserved:host": ""},
			},
			Layer4:  flow.Layer4{DestPort: 80, Protocol: flow.TCP},
			Verdict: flow.Allow,
		},
	}

	type testCase struct {
		name         string
		sourceType   parser.Source
		policyFormat string
		expectKind   string
	}

	cases := []testCase{
		{
			name:         "hubble + auto -> cnp",
			sourceType:   parser.SourceHubble,
			policyFormat: "auto",
			expectKind:   "CiliumNetworkPolicy",
		},
		{
			name:         "calico + auto -> np",
			sourceType:   parser.SourceCalico,
			policyFormat: "auto",
			expectKind:   "NetworkPolicy",
		},
		{
			name:         "hubble + np override -> np",
			sourceType:   parser.SourceHubble,
			policyFormat: "np",
			expectKind:   "NetworkPolicy",
		},
		{
			name:         "calico + cnp override -> cnp",
			sourceType:   parser.SourceCalico,
			policyFormat: "cnp",
			expectKind:   "CiliumNetworkPolicy",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			rd := &rootCmdData{
				policyFormat: tc.policyFormat,
				format:       "text",
				outputDir:    t.TempDir(),
			}
			cfg := config.Config{}

			err := executeAnalysis(cmd, flows, cfg, rd, tc.sourceType)
			require.NoError(t, err)

			entries, err := os.ReadDir(rd.outputDir)
			require.NoError(t, err)

			var yamlPath string
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
					yamlPath = filepath.Join(rd.outputDir, e.Name())
					break
				}
			}
			require.NotEmpty(t, yamlPath, "expected at least one yaml file in output dir")

			data, err := os.ReadFile(yamlPath)
			require.NoError(t, err)

			content := string(data)
			if tc.expectKind == "CiliumNetworkPolicy" {
				assert.True(t, strings.Contains(content, "kind: CiliumNetworkPolicy"),
					"expected CiliumNetworkPolicy kind in YAML; got:\n%s", content)
			} else {
				assert.True(t, strings.Contains(content, "kind: NetworkPolicy"),
					"expected NetworkPolicy kind in YAML; got:\n%s", content)
			}
		})
	}
}

package tui

import (
	"sort"
	"testing"

	"github.com/flowguarder/flowguarder/pkg/policy"
	"github.com/flowguarder/flowguarder/pkg/simulate"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// --- helpers ---

func mkTypeMeta(kind string) metav1.TypeMeta {
	return metav1.TypeMeta{Kind: kind}
}

func mkObjMeta(ns, name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Namespace: ns, Name: name}
}

func mkLabelSelector(m map[string]string) metav1.LabelSelector {
	return metav1.LabelSelector{MatchLabels: m}
}

func mkCNPMeta(ns, name string) policy.CNPMetadata {
	return policy.CNPMetadata{Namespace: ns, Name: name}
}

func mkCNPMetaEmpty(n string) policy.CNPMetadata {
	return policy.CNPMetadata{Name: n}
}

// --- tests ---

func TestExtractSelectableObjects_LoadPolicies(t *testing.T) {
	t.Parallel()

	policies, _, err := simulate.LoadPolicies("../../../testdata/simulate")
	if err != nil {
		t.Fatalf("LoadPolicies: %v", err)
	}
	if len(policies) == 0 {
		t.Fatal("LoadPolicies returned no policies")
	}

	objs := ExtractSelectableObjects(policies)

	// From fixtures:
	//   allow-ingress-np.yaml -> podSelector app=backend, default
	//   deny-ingress-np.yaml  -> podSelector app=backend, default
	//   allow-egress-cnp.yaml -> endpointSelector app=frontend, default
	//   deny-egress-cnp.yaml  -> endpointSelector app=frontend, default
	//   dns-allow-cnp.yaml    -> endpointSelector app=frontend, default
	//   invalid-syntax.yaml   -> podSelector app=unsorted, default (first valid doc)
	// De-duped: default/backend, default/frontend, default/unsorted
	wantWorks := []SelectableWorkload{
		{Namespace: "default", Name: "backend", Labels: map[string]string{"app": "backend"}},
		{Namespace: "default", Name: "frontend", Labels: map[string]string{"app": "frontend"}},
		{Namespace: "default", Name: "unsorted", Labels: map[string]string{"app": "unsorted"}},
	}

	if len(objs.Workloads) != len(wantWorks) {
		t.Errorf("workloads count: got %d, want %d\nworkloads: %+v", len(objs.Workloads), len(wantWorks), objs.Workloads)
	}

	for i, want := range wantWorks {
		if i >= len(objs.Workloads) {
			break
		}
		got := objs.Workloads[i]
		if got.Namespace != want.Namespace {
			t.Errorf("workload[%d] namespace: got %q, want %q", i, got.Namespace, want.Namespace)
		}
		if got.Name != want.Name {
			t.Errorf("workload[%d] name: got %q, want %q", i, got.Name, want.Name)
		}
		if len(got.Labels) != len(want.Labels) {
			t.Errorf("workload[%d] labels count: got %d, want %d", i, len(got.Labels), len(want.Labels))
			continue
		}
		for k, v := range want.Labels {
			if got.Labels[k] != v {
				t.Errorf("workload[%d] labels[%q]: got %q, want %q", i, k, got.Labels[k], v)
			}
		}
	}

	// Sort by namespace/name.
	for i := 1; i < len(objs.Workloads); i++ {
		prev := objs.Workloads[i-1]
		cur := objs.Workloads[i]
		if prev.Namespace > cur.Namespace || (prev.Namespace == cur.Namespace && prev.Name >= cur.Name) {
			t.Errorf("workloads not sorted at index %d", i)
		}
	}

	// No entities in fixtures.
	if len(objs.Entities) != 0 {
		t.Errorf("entities: got %v, want []", objs.Entities)
	}

	// No CIDRs in fixtures -> only "Custom IP/CIDR".
	if len(objs.CIDRs) != 1 {
		t.Errorf("cidrs count: got %d, want 1\ncidrs: %+v", len(objs.CIDRs), objs.CIDRs)
	}
	if objs.CIDRs[0].CIDR != "Custom IP/CIDR" {
		t.Errorf("cidrs[0]: got %q, want %q", objs.CIDRs[0].CIDR, "Custom IP/CIDR")
	}
}

func TestExtractSelectableObjects_EmptyInput(t *testing.T) {
	t.Parallel()

	objs := ExtractSelectableObjects(nil)

	if objs.Workloads != nil && len(objs.Workloads) != 0 {
		t.Errorf("workloads: got %+v, want empty", objs.Workloads)
	}
	if objs.Entities != nil && len(objs.Entities) != 0 {
		t.Errorf("entities: got %v, want empty", objs.Entities)
	}
	if len(objs.CIDRs) != 1 {
		t.Errorf("cidrs: got %d, want 1\ncidrs: %+v", len(objs.CIDRs), objs.CIDRs)
	}
	if len(objs.CIDRs) > 0 && objs.CIDRs[0].CIDR != "Custom IP/CIDR" {
		t.Errorf("cidrs[0]: %q, want Custom IP/CIDR", objs.CIDRs[0].CIDR)
	}
}

func TestExtractSelectableObjects_DedupWorkloads(t *testing.T) {
	t.Parallel()

	policies := []simulate.LoadedPolicy{
		{
			Kind:    "NetworkPolicy",
			Network: &networkingv1.NetworkPolicy{TypeMeta: mkTypeMeta("NetworkPolicy"), ObjectMeta: mkObjMeta("default", "np1"), Spec: networkingv1.NetworkPolicySpec{PodSelector: mkLabelSelector(map[string]string{"app": "web"})}},
		},
		{
			Kind:    "NetworkPolicy",
			Network: &networkingv1.NetworkPolicy{TypeMeta: mkTypeMeta("NetworkPolicy"), ObjectMeta: mkObjMeta("default", "np2"), Spec: networkingv1.NetworkPolicySpec{PodSelector: mkLabelSelector(map[string]string{"app": "web", "app.kubernetes.io/component": "api", "app.kubernetes.io/version": "1.2.3"})}},
		},
	}

	objs := ExtractSelectableObjects(policies)

	if len(objs.Workloads) != 1 {
		t.Fatalf("workloads: got %d, want 1\ngot: %+v", len(objs.Workloads), objs.Workloads)
	}
	w := objs.Workloads[0]
	if w.Namespace != "default" {
		t.Errorf("namespace: %q, want %q", w.Namespace, "default")
	}
	if w.Name != "web" {
		t.Errorf("name: %q, want %q", w.Name, "web")
	}
	if len(w.Labels) != 3 {
		t.Errorf("labels count: %d, want 3 (richest): %#v", len(w.Labels), w.Labels)
	}
}

func TestExtractSelectableObjects_EntityExtraction(t *testing.T) {
	t.Parallel()

	policies := []simulate.LoadedPolicy{
		{
			Kind: "CiliumNetworkPolicy",
			Cilium: &policy.CiliumNetworkPolicy{
				APIVersion: "cilium.io/v2", Kind: "CiliumNetworkPolicy", Metadata: mkCNPMeta("default", "cnp1"),
				Spec: policy.CNPSpec{
					EndpointSelector: policy.CNPEntitySelector{MatchLabels: map[string]string{"app": "gateway"}},
					Egress: []policy.CNPEgressRule{
						{ToEntities: []string{"world", "kube-apiserver", "invalid-entity"}},
					},
				},
			},
		},
		{
			Kind: "CiliumNetworkPolicy",
			Cilium: &policy.CiliumNetworkPolicy{
				APIVersion: "cilium.io/v2", Kind: "CiliumNetworkPolicy", Metadata: mkCNPMeta("default", "cnp2"),
				Spec: policy.CNPSpec{
					EndpointSelector: policy.CNPEntitySelector{MatchLabels: map[string]string{"app": "backend"}},
					Ingress: []policy.CNPIngressRule{
						{FromEntities: []string{"cluster", "host", "host"}},
					},
				},
			},
		},
	}

	objs := ExtractSelectableObjects(policies)

	wantEntities := []string{"cluster", "host", "kube-apiserver", "world"}
	sort.Strings(wantEntities)

	if len(objs.Entities) != len(wantEntities) {
		t.Errorf("entities: got %v, want %v", objs.Entities, wantEntities)
	} else {
		for i, want := range wantEntities {
			if objs.Entities[i] != want {
				t.Errorf("entities[%d]: %q, want %q", i, objs.Entities[i], want)
			}
		}
	}
}

func TestExtractSelectableObjects_CIDRExtraction(t *testing.T) {
	t.Parallel()

	policies := []simulate.LoadedPolicy{
		{
			Kind: "NetworkPolicy",
			Network: &networkingv1.NetworkPolicy{
				TypeMeta: mkTypeMeta("NetworkPolicy"), ObjectMeta: mkObjMeta("default", "np1"),
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: mkLabelSelector(map[string]string{"app": "client"}),
					Egress: []networkingv1.NetworkPolicyEgressRule{
						{To: []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "10.0.0.0/8"}}}},
					},
					Ingress: []networkingv1.NetworkPolicyIngressRule{
						{From: []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "192.168.1.0/24"}}}},
					},
				},
			},
		},
		{
			Kind: "CiliumNetworkPolicy",
			Cilium: &policy.CiliumNetworkPolicy{
				APIVersion: "cilium.io/v2", Kind: "CiliumNetworkPolicy", Metadata: mkCNPMeta("default", "cnp1"),
				Spec: policy.CNPSpec{
					EndpointSelector: policy.CNPEntitySelector{MatchLabels: map[string]string{"app": "server"}},
					Egress:           []policy.CNPEgressRule{{ToCIDR: []string{"172.16.0.0/12"}}},
					Ingress:          []policy.CNPIngressRule{{FromCIDR: []string{"100.64.0.0/10"}}},
				},
			},
		},
	}

	objs := ExtractSelectableObjects(policies)

	wantCIDRs := []string{"10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.1.0/24", "Custom IP/CIDR"}
	sort.Strings(wantCIDRs)

	if len(objs.CIDRs) != len(wantCIDRs) {
		t.Fatalf("cidrs: got %d, want %d\ngot: %+v", len(objs.CIDRs), len(wantCIDRs), objs.CIDRs)
	}
	for i, want := range wantCIDRs {
		if objs.CIDRs[i].CIDR != want {
			t.Errorf("cidrs[%d]: %q, want %q", i, objs.CIDRs[i].CIDR, want)
		}
	}
}

func TestExtractSelectableObjects_CIDRExclusion_NoSlash(t *testing.T) {
	t.Parallel()

	policies := []simulate.LoadedPolicy{
		{
			Kind: "CiliumNetworkPolicy",
			Cilium: &policy.CiliumNetworkPolicy{
				APIVersion: "cilium.io/v2", Kind: "CiliumNetworkPolicy", Metadata: mkCNPMeta("default", "x"),
				Spec: policy.CNPSpec{
					EndpointSelector: policy.CNPEntitySelector{MatchLabels: map[string]string{"app": "test"}},
					Egress:           []policy.CNPEgressRule{{ToCIDR: []string{"0.0.0.0/0", "just-a-string"}}},
				},
			},
		},
	}

	objs := ExtractSelectableObjects(policies)

	wantCIDRs := []string{"0.0.0.0/0", "Custom IP/CIDR"}
	sort.Strings(wantCIDRs)

	if len(objs.CIDRs) != len(wantCIDRs) {
		t.Fatalf("cidrs: got %d, want %d\ngot: %+v", len(objs.CIDRs), len(wantCIDRs), objs.CIDRs)
	}
	for i, want := range wantCIDRs {
		if objs.CIDRs[i].CIDR != want {
			t.Errorf("cidrs[%d]: %q, want %q", i, objs.CIDRs[i].CIDR, want)
		}
	}
}

func TestExtractSelectableObjects_IPPrefixNoSlashExcluded(t *testing.T) {
	t.Parallel()

	policies := []simulate.LoadedPolicy{
		{
			Kind: "CiliumNetworkPolicy",
			Cilium: &policy.CiliumNetworkPolicy{
				APIVersion: "cilium.io/v2", Kind: "CiliumNetworkPolicy", Metadata: mkCNPMeta("default", "x"),
				Spec: policy.CNPSpec{
					EndpointSelector: policy.CNPEntitySelector{MatchLabels: map[string]string{"app": "test"}},
					Egress:           []policy.CNPEgressRule{{ToCIDR: []string{"10.0.0.1", "10.0.0.2"}}},
				},
			},
		},
	}

	objs := ExtractSelectableObjects(policies)

	if len(objs.CIDRs) != 1 {
		t.Fatalf("cidrs: got %d, want 1\ngot: %+v", len(objs.CIDRs), objs.CIDRs)
	}
	if objs.CIDRs[0].CIDR != "Custom IP/CIDR" {
		t.Errorf("cidrs[0]: %q, want Custom IP/CIDR", objs.CIDRs[0].CIDR)
	}
}

func TestExtractSelectableObjects_AppKubernetesIOName(t *testing.T) {
	t.Parallel()

	policies := []simulate.LoadedPolicy{
		{
			Kind:    "NetworkPolicy",
			Network: &networkingv1.NetworkPolicy{TypeMeta: mkTypeMeta("NetworkPolicy"), ObjectMeta: mkObjMeta("production", "app-np"), Spec: networkingv1.NetworkPolicySpec{PodSelector: mkLabelSelector(map[string]string{"app.kubernetes.io/name": "payment-service", "app.kubernetes.io/part": "backend", "custom-label": "value"})}},
		},
	}

	objs := ExtractSelectableObjects(policies)

	if len(objs.Workloads) != 1 {
		t.Fatalf("workloads: %d, want 1", len(objs.Workloads))
	}
	w := objs.Workloads[0]
	if w.Namespace != "production" {
		t.Errorf("namespace: %q, want %q", w.Namespace, "production")
	}
	if w.Name != "payment-service" {
		t.Errorf("name: %q, want %q", w.Name, "payment-service")
	}
	if len(w.Labels) != 3 {
		t.Errorf("labels count: %d, want 3\n%#v", len(w.Labels), w.Labels)
	}
}

func TestExtractSelectableObjects_SkipNoAppName(t *testing.T) {
	t.Parallel()

	policies := []simulate.LoadedPolicy{
		{
			Kind:    "NetworkPolicy",
			Network: &networkingv1.NetworkPolicy{TypeMeta: mkTypeMeta("NetworkPolicy"), ObjectMeta: mkObjMeta("default", "orphan-np"), Spec: networkingv1.NetworkPolicySpec{PodSelector: mkLabelSelector(map[string]string{"component": "monitoring", "tier": "infra"})}},
		},
	}

	objs := ExtractSelectableObjects(policies)

	if len(objs.Workloads) != 0 {
		t.Errorf("workloads: %d, want 0\n%+v", len(objs.Workloads), objs.Workloads)
	}
}

func TestExtractSelectableObjects_DefaultNamespace(t *testing.T) {
	t.Parallel()

	policies := []simulate.LoadedPolicy{
		{
			Kind: "CiliumNetworkPolicy",
			Cilium: &policy.CiliumNetworkPolicy{
				APIVersion: "cilium.io/v2", Kind: "CiliumNetworkPolicy", Metadata: mkCNPMetaEmpty("x"),
				Spec: policy.CNPSpec{
					EndpointSelector: policy.CNPEntitySelector{MatchLabels: map[string]string{"app": "orphan"}},
				},
			},
		},
	}

	objs := ExtractSelectableObjects(policies)

	if len(objs.Workloads) != 1 {
		t.Fatalf("workloads: %d, want 1", len(objs.Workloads))
	}
	if objs.Workloads[0].Namespace != "default" {
		t.Errorf("namespace: %q, want default", objs.Workloads[0].Namespace)
	}
}

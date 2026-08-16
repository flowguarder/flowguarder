package simulate

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// nptestDir is the relative path to the shared testdata/simulate directory.
const npFixtureDir = "../../testdata/simulate"

// ---------------------------------------------------------------------------
// Helper names: chosen to NOT collide with eval_cnp_test.go
// (buildCNP, buildCNPInline, matchLabel, check, fixtureDir, mustFixture,
//  baseFixtureDir, check[T]) or loader_test.go (baseFixtureDir).
// ---------------------------------------------------------------------------

// npMeta builds a v1.NetworkPolicyMetadata equivalent via labels.
func npNS(ns string, name string) LoadedPolicy {
	if ns == "" {
		ns = "default"
	}
	return LoadedPolicy{
		File: name + ".yaml",
		Kind: "NetworkPolicy",
	}
}

// buildNP constructs a NetworkPolicy LoadedPolicy inline.
func buildNP(name, ns string, sel map[string]string,
	ingress []v1.NetworkPolicyIngressRule, egress []v1.NetworkPolicyEgressRule,
) LoadedPolicy {
	if ns == "" {
		ns = "default"
	}
	p := npNS(ns, name)
	p.Network = &v1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: v1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: sel,
			},
		},
	}
	if len(ingress) > 0 {
		p.Network.Spec.Ingress = ingress
	}
	if len(egress) > 0 {
		p.Network.Spec.Egress = egress
	}
	return p
}

// buildNPEmptyIngress builds a default-deny policy with an empty ingress list.
func buildNPEmptyIngress(name, ns string, sel map[string]string) LoadedPolicy {
	if ns == "" {
		ns = "default"
	}
	p := npNS(ns, name)
	p.Network = &v1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: v1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: sel,
			},
			Ingress: []v1.NetworkPolicyIngressRule{},
		},
	}
	return p
}

// buildNPEmptyEgress builds a default-deny policy with an empty egress list.
func buildNPEmptyEgress(name, ns string, sel map[string]string) LoadedPolicy {
	if ns == "" {
		ns = "default"
	}
	p := npNS(ns, name)
	p.Network = &v1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: v1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: sel,
			},
			Egress: []v1.NetworkPolicyEgressRule{},
		},
	}
	return p
}

// npIng builds an ingress rule with From peers and ports.
func npIng(from []v1.NetworkPolicyPeer, ports []v1.NetworkPolicyPort) v1.NetworkPolicyIngressRule {
	return v1.NetworkPolicyIngressRule{
		From:  from,
		Ports: ports,
	}
}

// npEgr builds an egress rule with To peers and ports.
func npEgr(to []v1.NetworkPolicyPeer, ports []v1.NetworkPolicyPort) v1.NetworkPolicyEgressRule {
	return v1.NetworkPolicyEgressRule{
		To:    to,
		Ports: ports,
	}
}

// npPort builds a NetworkPolicyPort.
func npPort(protocol string, port int32) v1.NetworkPolicyPort {
	p := corev1.Protocol(protocol)
	return v1.NetworkPolicyPort{
		Protocol: &p,
		Port:     intstrPtr(intstr.FromInt32(port)),
	}
}

// npPortAny builds a port rule with any protocol.
func npPortAny(port int32) v1.NetworkPolicyPort {
	return v1.NetworkPolicyPort{
		Port: intstrPtr(intstr.FromInt32(port)),
	}
}

// npPortNilProto builds a port rule with nil protocol (any).
func npPortNilProto(port int32) v1.NetworkPolicyPort {
	return v1.NetworkPolicyPort{
		Port: intstrPtr(intstr.FromInt32(port)),
	}
}

func intstrPtr(v intstr.IntOrString) *intstr.IntOrString {
	return &v
}

// npPodSel builds a PodSelector peer.
func npPodSel(labels map[string]string) v1.NetworkPolicyPeer {
	return v1.NetworkPolicyPeer{
		PodSelector: &metav1.LabelSelector{
			MatchLabels: labels,
		},
	}
}

// npNsSel builds a NamespaceSelector peer (empty = match all).
func npNsSel(matchLabels map[string]string) v1.NetworkPolicyPeer {
	return v1.NetworkPolicyPeer{
		NamespaceSelector: &metav1.LabelSelector{
			MatchLabels: matchLabels,
		},
	}
}

// npCombinedSel builds a peer with both PodSelector and NamespaceSelector.
func npCombinedSel(labels map[string]string, nsLabels map[string]string) v1.NetworkPolicyPeer {
	return v1.NetworkPolicyPeer{
		PodSelector:       &metav1.LabelSelector{MatchLabels: labels},
		NamespaceSelector: &metav1.LabelSelector{MatchLabels: nsLabels},
	}
}

// npIPBlock builds an IPBlock peer.
func npIPBlock(cidr string, except []string) v1.NetworkPolicyPeer {
	return v1.NetworkPolicyPeer{
		IPBlock: &v1.IPBlock{
			CIDR:   cidr,
			Except: except,
		},
	}
}

// npSelExpr builds a PodSelector with MatchExpressions.
func npSelExpr(key string, op metav1.LabelSelectorOperator, vals []string) v1.NetworkPolicyPeer {
	return v1.NetworkPolicyPeer{
		PodSelector: &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: key, Operator: op, Values: vals},
			},
		},
	}
}

// npCheck is a generic assertion helper (does NOT collide with check[T] from the other file).
func npCheck[T comparable](t *testing.T, label string, want, got T) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %v; want %v", label, got, want)
	}
}

// mustReadFixture reads a YAML fixture file; panics on error.
func mustReadFixture(name string) []byte {
	data, err := os.ReadFile(filepath.Join(npFixtureDir, name))
	if err != nil {
		panic("read fixture " + name + ": " + err.Error())
	}
	return data
}

// ---------------------------------------------------------------------------
// Table-driven tests for EvaluateNetworkPolicy.
// ---------------------------------------------------------------------------

func TestEvaluateNetworkPolicy(t *testing.T) {
	t.Parallel()

	frontend := Endpoint{Namespace: "default", Labels: map[string]string{"app": "frontend"}}
	backend := Endpoint{Namespace: "default", Labels: map[string]string{"app": "backend"}}
	unrelated := Endpoint{Namespace: "default", Labels: map[string]string{"app": "unrelated"}}

	// --- Helpers for inline construction ---
	ingPort := []v1.NetworkPolicyPort{npPort("TCP", 8080)}

	tests := []struct {
		name      string
		src, dst  Endpoint
		traffic   Traffic
		policies  []LoadedPolicy
		l7        *Traffic
		wantIng   Verdict
		wantEgr   Verdict
		wantFiles []string
	}{
		// ==================== INGRESS ====================

		// --- ingress allow ---
		{
			name: "ingress-allow-podSelector-same-ns",
			src:  frontend, dst: backend,
			traffic: Traffic{Port: 8080, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("allow-fe", "default", map[string]string{"app": "backend"},
					[]v1.NetworkPolicyIngressRule{npIng([]v1.NetworkPolicyPeer{npPodSel(map[string]string{"app": "frontend"})}, ingPort)},
					nil),
			},
			wantIng:   VerdictAllow,
			wantFiles: []string{"allow-fe.yaml"},
		},

		// --- ingress deny ---
		{
			name: "ingress-deny-podSelector-mismatch",
			src:  unrelated, dst: backend,
			traffic: Traffic{Port: 8080, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("deny-fe", "default", map[string]string{"app": "backend"},
					[]v1.NetworkPolicyIngressRule{npIng([]v1.NetworkPolicyPeer{npPodSel(map[string]string{"app": "frontend"})}, ingPort)},
					nil),
			},
			wantIng:   VerdictDeny,
			wantFiles: []string{"deny-fe.yaml"},
		},

		// --- ingress undetermined (scope mismatch) ---
		{
			name: "ingress-undetermined-scope-mismatch",
			src:  frontend, dst: backend,
			traffic: Traffic{Port: 8080, Protocol: "TCP"},
			policies: []LoadedPolicy{
				// Policy targets app=backend but in "other" namespace.
				buildNP("other-ns", "other", map[string]string{"app": "backend"},
					[]v1.NetworkPolicyIngressRule{npIng([]v1.NetworkPolicyPeer{npPodSel(map[string]string{"app": "frontend"})}, ingPort)},
					nil),
			},
			wantIng: VerdictUndetermined,
		},

		// --- ingress nil Ingress (not covered at all) ---
		{
			name: "ingress-nil-not-covered",
			src:  frontend, dst: backend,
			traffic: Traffic{Port: 8080, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("no-ingress-rule", "default", map[string]string{"app": "backend"},
					nil, /* ingress = nil → not covered */
					[]v1.NetworkPolicyEgressRule{npEgr(nil, nil)}),
			},
			wantIng: VerdictUndetermined,
		},

		// ==================== EGRESS ====================

		// --- egress allow (exercises the fixed bug) ---
		// frontend (src) → backend (dst), egress policy on frontend with To: app=backend
		// Before fix: target=dstEp=backend, but dstEp was wrongly pointing to backend in swapped args...
		// Actually the swap: evalNPDir(dst, src, ..., npEgress) means
		// srcEp in evalNPDir = flow dst = backend, dstEp = flow src = frontend.
		// Bug: egress used &dstEp = &frontend → peer match failed.
		// Fix: use &srcEp = &backend → peer matches To: app=backend.
		{
			name: "egress-allow-podSelector-to-match",
			src:  frontend, dst: backend,
			traffic: Traffic{Port: 8080, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("allow-e2b", "default", map[string]string{"app": "frontend"},
					nil, /* no ingress */
					[]v1.NetworkPolicyEgressRule{npEgr([]v1.NetworkPolicyPeer{npPodSel(map[string]string{"app": "backend"})}, []v1.NetworkPolicyPort{npPort("TCP", 8080)})}),
			},
			wantEgr:   VerdictAllow,
			wantFiles: []string{"allow-e2b.yaml"},
		},

		// --- egress deny: peer doesn't match ---
		{
			name: "egress-deny-podSelector-mismatch",
			src:  frontend, dst: backend,
			traffic: Traffic{Port: 8080, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("deny-e2u", "default", map[string]string{"app": "frontend"},
					nil,
					[]v1.NetworkPolicyEgressRule{npEgr([]v1.NetworkPolicyPeer{npPodSel(map[string]string{"app": "unrelated"})}, []v1.NetworkPolicyPort{npPort("TCP", 8080)})}),
			},
			wantEgr:   VerdictDeny,
			wantFiles: []string{"deny-e2u.yaml"},
		},

		// --- egress undetermined: egress is nil on selector policy ---
		{
			name: "egress-undetermined-nil-egress",
			src:  frontend, dst: backend,
			traffic: Traffic{Port: 8080, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("no-egress-rule", "default", map[string]string{"app": "frontend"},
					nil, nil),
			},
			wantEgr: VerdictUndetermined,
		},

		// ==================== POD SELECTOR ====================

		// --- podSelector-only same-namespace matches ---
		{
			name:    "podSelector-same-ns-ingress",
			src:     Endpoint{Namespace: "prod", Labels: map[string]string{"app": "reader"}},
			dst:     Endpoint{Namespace: "prod", Labels: map[string]string{"app": "db"}},
			traffic: Traffic{Port: 5432, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("db-ingress", "prod", map[string]string{"app": "db"},
					[]v1.NetworkPolicyIngressRule{npIng([]v1.NetworkPolicyPeer{npPodSel(map[string]string{"app": "reader"})}, []v1.NetworkPolicyPort{npPort("TCP", 5432)})},
					nil),
			},
			wantIng:   VerdictAllow,
			wantFiles: []string{"db-ingress.yaml"},
		},

		// --- podSelector-only cross-namespace → podSelector alone implies same-ns ---
		// Note: the policy's scope check already filters by namespace, so a
		// podSelector-only rule can't match a peer in a different namespace.
		{
			name:    "podSelector-cross-ns-deny-by-scope",
			src:     Endpoint{Namespace: "prod", Labels: map[string]string{"app": "reader"}},
			dst:     Endpoint{Namespace: "staging", Labels: map[string]string{"app": "db"}},
			traffic: Traffic{Port: 5432, Protocol: "TCP"},
			policies: []LoadedPolicy{
				// Policy is in "prod", dst is in "staging" → scope mismatch.
				buildNP("bad-scope", "prod", map[string]string{"app": "db"},
					[]v1.NetworkPolicyIngressRule{npIng([]v1.NetworkPolicyPeer{npPodSel(map[string]string{"app": "reader"})}, []v1.NetworkPolicyPort{npPort("TCP", 5432)})},
					nil),
			},
			wantIng: VerdictUndetermined,
		},

		// ==================== NAMESPACE SELECTOR ====================

		// --- namespaceSelector {} (all namespaces) → cross-ns allow ---
		{
			name:    "nsSel-all-cross-ns-allow",
			src:     Endpoint{Namespace: "kube-system", Labels: map[string]string{"tier": "control-plane"}},
			dst:     Endpoint{Namespace: "prod", Labels: map[string]string{"app": "db"}},
			traffic: Traffic{Port: 5432, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("cross-ns-db", "prod", map[string]string{"app": "db"},
					[]v1.NetworkPolicyIngressRule{npIng([]v1.NetworkPolicyPeer{npNsSel(nil)}, []v1.NetworkPolicyPort{npPort("TCP", 5432)})},
					nil),
			},
			wantIng:   VerdictAllow,
			wantFiles: []string{"cross-ns-db.yaml"},
		},

		// --- namespaceSelector specific name match ---
		{
			name:    "nsSel-specific-match",
			src:     Endpoint{Namespace: "other", Labels: map[string]string{"app": "client"}},
			dst:     Endpoint{Namespace: "prod", Labels: map[string]string{"app": "db"}},
			traffic: Traffic{Port: 5432, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("other-ns-db", "prod", map[string]string{"app": "db"},
					[]v1.NetworkPolicyIngressRule{npIng([]v1.NetworkPolicyPeer{npNsSel(map[string]string{"kubernetes.io/metadata.name": "other"})}, []v1.NetworkPolicyPort{npPort("TCP", 5432)})},
					nil),
			},
			wantIng:   VerdictAllow,
			wantFiles: []string{"other-ns-db.yaml"},
		},

		// --- namespaceSelector specific name mismatch ---
		{
			name:    "nsSel-specific-mismatch",
			src:     Endpoint{Namespace: "other", Labels: map[string]string{"app": "client"}},
			dst:     Endpoint{Namespace: "prod", Labels: map[string]string{"app": "db"}},
			traffic: Traffic{Port: 5432, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("other-ns-db", "prod", map[string]string{"app": "db"},
					[]v1.NetworkPolicyIngressRule{npIng([]v1.NetworkPolicyPeer{npNsSel(map[string]string{"kubernetes.io/metadata.name": "different"})}, []v1.NetworkPolicyPort{npPort("TCP", 5432)})},
					nil),
			},
			wantIng:   VerdictDeny,
			wantFiles: []string{"other-ns-db.yaml"},
		},

		// ==================== COMBINED POD+NS SELECTOR ====================

		{
			name:    "combined-pod+ns-match",
			src:     Endpoint{Namespace: "staging", Labels: map[string]string{"app": "worker"}},
			dst:     Endpoint{Namespace: "prod", Labels: map[string]string{"app": "scheduler"}},
			traffic: Traffic{Port: 9090, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("combined", "prod", map[string]string{"app": "scheduler"},
					[]v1.NetworkPolicyIngressRule{npIng([]v1.NetworkPolicyPeer{npCombinedSel(
						map[string]string{"app": "worker"},
						map[string]string{"kubernetes.io/metadata.name": "staging"},
					)}, []v1.NetworkPolicyPort{npPort("TCP", 9090)})},
					nil),
			},
			wantIng:   VerdictAllow,
			wantFiles: []string{"combined.yaml"},
		},

		{
			name:    "combined-pod+ns-pod-mismatch",
			src:     Endpoint{Namespace: "staging", Labels: map[string]string{"app": "bad"}},
			dst:     Endpoint{Namespace: "prod", Labels: map[string]string{"app": "scheduler"}},
			traffic: Traffic{Port: 9090, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("combined", "prod", map[string]string{"app": "scheduler"},
					[]v1.NetworkPolicyIngressRule{npIng([]v1.NetworkPolicyPeer{npCombinedSel(
						map[string]string{"app": "worker"},
						map[string]string{"kubernetes.io/metadata.name": "staging"},
					)}, []v1.NetworkPolicyPort{npPort("TCP", 9090)})},
					nil),
			},
			wantIng:   VerdictDeny,
			wantFiles: []string{"combined.yaml"},
		},

		{
			name:    "combined-pod+ns-ns-mismatch",
			src:     Endpoint{Namespace: "other", Labels: map[string]string{"app": "worker"}},
			dst:     Endpoint{Namespace: "prod", Labels: map[string]string{"app": "scheduler"}},
			traffic: Traffic{Port: 9090, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("combined", "prod", map[string]string{"app": "scheduler"},
					[]v1.NetworkPolicyIngressRule{npIng([]v1.NetworkPolicyPeer{npCombinedSel(
						map[string]string{"app": "worker"},
						map[string]string{"kubernetes.io/metadata.name": "staging"},
					)}, []v1.NetworkPolicyPort{npPort("TCP", 9090)})},
					nil),
			},
			wantIng:   VerdictDeny,
			wantFiles: []string{"combined.yaml"},
		},

		// ==================== IP BLOCK ====================

		// --- ipBlock allow ---
		{
			name:    "ipblock-allow-cidr-match",
			src:     Endpoint{Namespace: "default", IP: "203.0.113.5"},
			dst:     Endpoint{Namespace: "default", Labels: map[string]string{"app": "public-svc"}},
			traffic: Traffic{Port: 443, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("external-443", "default", map[string]string{"app": "public-svc"},
					[]v1.NetworkPolicyIngressRule{npIng([]v1.NetworkPolicyPeer{npIPBlock("203.0.113.0/24", nil)}, []v1.NetworkPolicyPort{npPort("TCP", 443)})},
					nil),
			},
			wantIng:   VerdictAllow,
			wantFiles: []string{"external-443.yaml"},
		},

		// --- ipBlock except → deny ---
		{
			name:    "ipblock-except-deny",
			src:     Endpoint{Namespace: "default", IP: "203.0.113.100"},
			dst:     Endpoint{Namespace: "default", Labels: map[string]string{"app": "internal"}},
			traffic: Traffic{Port: 443, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("ext-except", "default", map[string]string{"app": "internal"},
					[]v1.NetworkPolicyIngressRule{npIng([]v1.NetworkPolicyPeer{npIPBlock("203.0.113.0/24", []string{"203.0.113.100/32"})}, []v1.NetworkPolicyPort{npPort("TCP", 443)})},
					nil),
			},
			wantIng:   VerdictDeny,
			wantFiles: []string{"ext-except.yaml"},
		},

		{
			name:    "ipblock-not-in-cidr-undetermined",
			src:     Endpoint{Namespace: "default", IP: "192.168.1.5"},
			dst:     Endpoint{Namespace: "default", Labels: map[string]string{"app": "svc"}},
			traffic: Traffic{Port: 80, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("cidr-only", "default", map[string]string{"app": "svc"},
					[]v1.NetworkPolicyIngressRule{npIng([]v1.NetworkPolicyPeer{npIPBlock("10.0.0.0/8", nil)}, []v1.NetworkPolicyPort{npPort("TCP", 80)})},
					nil),
			},
			wantIng:   VerdictDeny,
			wantFiles: []string{"cidr-only.yaml"},
		},

		// --- ipBlock with empty IP on flow → deny (no match) ---
		{
			name:    "ipblock-empty-flow-ip-deny",
			src:     Endpoint{Namespace: "default"}, // No IP
			dst:     Endpoint{Namespace: "default", Labels: map[string]string{"app": "svc"}},
			traffic: Traffic{Port: 80, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("no-ip-match", "default", map[string]string{"app": "svc"},
					[]v1.NetworkPolicyIngressRule{npIng([]v1.NetworkPolicyPeer{npIPBlock("10.0.0.0/8", nil)}, []v1.NetworkPolicyPort{npPort("TCP", 80)})},
					nil),
			},
			wantIng:   VerdictDeny,
			wantFiles: []string{"no-ip-match.yaml"},
		},

		// ==================== PORT MATCHING ====================

		// --- port match → allow ---
		{
			name: "port-match",
			src:  frontend, dst: backend,
			traffic: Traffic{Port: 8080, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("port-tcp-8080", "default", map[string]string{"app": "backend"},
					[]v1.NetworkPolicyIngressRule{npIng([]v1.NetworkPolicyPeer{npPodSel(map[string]string{"app": "frontend"})}, []v1.NetworkPolicyPort{npPort("TCP", 8080)})},
					nil),
			},
			wantIng:   VerdictAllow,
			wantFiles: []string{"port-tcp-8080.yaml"},
		},

		// --- port mismatch → deny ---
		{
			name: "port-mismatch-deny",
			src:  frontend, dst: backend,
			traffic: Traffic{Port: 9090, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("port-tcp-8080", "default", map[string]string{"app": "backend"},
					[]v1.NetworkPolicyIngressRule{npIng([]v1.NetworkPolicyPeer{npPodSel(map[string]string{"app": "frontend"})}, []v1.NetworkPolicyPort{npPort("TCP", 8080)})},
					nil),
			},
			wantIng:   VerdictDeny,
			wantFiles: []string{"port-tcp-8080.yaml"},
		},

		// --- protocol mismatch → deny ---
		{
			name: "protocol-mismatch-deny",
			src:  frontend, dst: backend,
			traffic: Traffic{Port: 8080, Protocol: "UDP"},
			policies: []LoadedPolicy{
				buildNP("proto-tcp", "default", map[string]string{"app": "backend"},
					[]v1.NetworkPolicyIngressRule{npIng([]v1.NetworkPolicyPeer{npPodSel(map[string]string{"app": "frontend"})}, []v1.NetworkPolicyPort{npPort("TCP", 8080)})},
					nil),
			},
			wantIng:   VerdictDeny,
			wantFiles: []string{"proto-tcp.yaml"},
		},

		// --- nil protocol (any protocol) → match ---
		{
			name: "rule-nil-protocol-any",
			src:  frontend, dst: backend,
			traffic: Traffic{Port: 8080, Protocol: "UDP"},
			policies: []LoadedPolicy{
				buildNP("any-proto", "default", map[string]string{"app": "backend"},
					[]v1.NetworkPolicyIngressRule{npIng([]v1.NetworkPolicyPeer{npPodSel(map[string]string{"app": "frontend"})}, []v1.NetworkPolicyPort{npPortAny(8080)})},
					nil),
			},
			wantIng:   VerdictAllow,
			wantFiles: []string{"any-proto.yaml"},
		},

		// --- nil port (any port) → match ---
		{
			name: "rule-nil-port-any",
			src:  frontend, dst: backend,
			traffic: Traffic{Port: 9090, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("any-port", "default", map[string]string{"app": "backend"},
					[]v1.NetworkPolicyIngressRule{npIng([]v1.NetworkPolicyPeer{npPodSel(map[string]string{"app": "frontend"})}, []v1.NetworkPolicyPort{npPortNilProto(0)})},
					nil),
			},
			wantIng:   VerdictAllow,
			wantFiles: []string{"any-port.yaml"},
		},

		// --- traffic port 0 = any → match ---
		{
			name: "traffic-port-0-any",
			src:  frontend, dst: backend,
			traffic: Traffic{Port: 0, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("gated-by-port", "default", map[string]string{"app": "backend"},
					[]v1.NetworkPolicyIngressRule{npIng([]v1.NetworkPolicyPeer{npPodSel(map[string]string{"app": "frontend"})}, []v1.NetworkPolicyPort{npPort("TCP", 80)})},
					nil),
			},
			wantIng:   VerdictAllow,
			wantFiles: []string{"gated-by-port.yaml"},
		},

		// ==================== DEFAULT-DENY ====================

		// --- empty ingress list → covered, no rules → deny ---
		{
			name: "default-deny-empty-ingress-list",
			src:  frontend, dst: backend,
			traffic: Traffic{Port: 80, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNPEmptyIngress("deny-ingress", "default", map[string]string{"app": "backend"}),
			},
			wantIng:   VerdictDeny,
			wantFiles: []string{"deny-ingress.yaml"},
		},

		// --- empty egress list → default deny ---
		{
			name: "default-deny-empty-egress-list",
			src:  frontend, dst: backend,
			traffic: Traffic{Port: 8080, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNPEmptyEgress("deny-egress", "default", map[string]string{"app": "frontend"}),
			},
			wantEgr:   VerdictDeny,
			wantFiles: []string{"deny-egress.yaml"},
		},

		// ==================== NO-PEER RULE ====================

		// --- rule with no peers → allow all (port-gated) ---
		{
			name: "no-peer-rule-allow-all",
			src:  unrelated, dst: backend,
			traffic: Traffic{Port: 8080, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("allow-scope", "default", map[string]string{"app": "backend"},
					[]v1.NetworkPolicyIngressRule{{}}, // empty rule = match all
					nil),
			},
			wantIng:   VerdictAllow,
			wantFiles: []string{"allow-scope.yaml"},
		},

		// --- no-peer rule with nil peers → allow all ---
		{
			name: "nil-peers-rule-allow-all",
			src:  unrelated, dst: backend,
			traffic: Traffic{Port: 8080, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("nil-peer", "default", map[string]string{"app": "backend"},
					[]v1.NetworkPolicyIngressRule{{From: nil, Ports: nil}},
					nil),
			},
			wantIng:   VerdictAllow,
			wantFiles: []string{"nil-peer.yaml"},
		},

		// ==================== MATCH EXPRESSIONS ====================

		// --- In operator match ---
		{
			name:    "matchExpr-in-match",
			src:     Endpoint{Namespace: "default", Labels: map[string]string{"env": "prod"}},
			dst:     Endpoint{Namespace: "default", Labels: map[string]string{"app": "app1"}},
			traffic: Traffic{Port: 80, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("expr-in", "default", map[string]string{"app": "app1"},
					[]v1.NetworkPolicyIngressRule{npIng([]v1.NetworkPolicyPeer{
						npSelExpr("env", metav1.LabelSelectorOpIn, []string{"prod", "staging"}),
					}, nil)},
					nil),
			},
			wantIng:   VerdictAllow,
			wantFiles: []string{"expr-in.yaml"},
		},

		// --- In operator no match → deny (policy covers dst, peer fails) ---
		{
			name:    "matchExpr-in-no-match",
			src:     Endpoint{Namespace: "default", Labels: map[string]string{"env": "dev"}},
			dst:     Endpoint{Namespace: "default", Labels: map[string]string{"app": "app1"}},
			traffic: Traffic{Port: 80, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("expr-in", "default", map[string]string{"app": "app1"},
					[]v1.NetworkPolicyIngressRule{npIng([]v1.NetworkPolicyPeer{
						npSelExpr("env", metav1.LabelSelectorOpIn, []string{"prod", "staging"}),
					}, nil)},
					nil),
			},
			wantIng:   VerdictDeny,
			wantFiles: []string{"expr-in.yaml"},
		},

		// --- NotIn operator match (label not in list) ---
		{
			name:    "matchExpr-notin-match",
			src:     Endpoint{Namespace: "default", Labels: map[string]string{"env": "dev"}},
			dst:     Endpoint{Namespace: "default", Labels: map[string]string{"app": "app1"}},
			traffic: Traffic{Port: 80, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("expr-notin", "default", map[string]string{"app": "app1"},
					[]v1.NetworkPolicyIngressRule{npIng([]v1.NetworkPolicyPeer{
						npSelExpr("env", metav1.LabelSelectorOpNotIn, []string{"prod", "staging"}),
					}, nil)},
					nil),
			},
			wantIng:   VerdictAllow,
			wantFiles: []string{"expr-notin.yaml"},
		},

		// --- NotIn operator no match → deny (policy covers, peer in list) ---
		{
			name:    "matchExpr-notin-no-match",
			src:     Endpoint{Namespace: "default", Labels: map[string]string{"env": "prod"}},
			dst:     Endpoint{Namespace: "default", Labels: map[string]string{"app": "app1"}},
			traffic: Traffic{Port: 80, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("expr-notin", "default", map[string]string{"app": "app1"},
					[]v1.NetworkPolicyIngressRule{npIng([]v1.NetworkPolicyPeer{
						npSelExpr("env", metav1.LabelSelectorOpNotIn, []string{"prod", "staging"}),
					}, nil)},
					nil),
			},
			wantIng:   VerdictDeny,
			wantFiles: []string{"expr-notin.yaml"},
		},

		// --- Exists operator match ---
		{
			name:    "matchExpr-exists-match",
			src:     Endpoint{Namespace: "default", Labels: map[string]string{"tier": "frontend"}},
			dst:     Endpoint{Namespace: "default", Labels: map[string]string{"app": "web"}},
			traffic: Traffic{Port: 80, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("expr-exists", "default", map[string]string{"app": "web"},
					[]v1.NetworkPolicyIngressRule{npIng([]v1.NetworkPolicyPeer{
						npSelExpr("tier", metav1.LabelSelectorOpExists, nil),
					}, nil)},
					nil),
			},
			wantIng:   VerdictAllow,
			wantFiles: []string{"expr-exists.yaml"},
		},

		// --- DoesNotExist operator match ---
		{
			name:    "matchExpr-doesNotExist-match",
			src:     Endpoint{Namespace: "default", Labels: map[string]string{"env": "prod"}},
			dst:     Endpoint{Namespace: "default", Labels: map[string]string{"app": "app1"}},
			traffic: Traffic{Port: 80, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("expr-dne", "default", map[string]string{"app": "app1"},
					[]v1.NetworkPolicyIngressRule{npIng([]v1.NetworkPolicyPeer{
						npSelExpr("debug", metav1.LabelSelectorOpDoesNotExist, nil),
					}, nil)},
					nil),
			},
			wantIng:   VerdictAllow,
			wantFiles: []string{"expr-dne.yaml"},
		},

		// --- DoesNotExist operator no match → deny (label exists) ---
		{
			name:    "matchExpr-doesNotExist-no-match",
			src:     Endpoint{Namespace: "default", Labels: map[string]string{"debug": "true"}},
			dst:     Endpoint{Namespace: "default", Labels: map[string]string{"app": "app1"}},
			traffic: Traffic{Port: 80, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("expr-dne", "default", map[string]string{"app": "app1"},
					[]v1.NetworkPolicyIngressRule{npIng([]v1.NetworkPolicyPeer{
						npSelExpr("debug", metav1.LabelSelectorOpDoesNotExist, nil),
					}, nil)},
					nil),
			},
			wantIng:   VerdictDeny,
			wantFiles: []string{"expr-dne.yaml"},
		},

		// ==================== MATCHING FILES ====================

		// --- allow: MatchingFiles contains the matching policy file ---
		{
			name: "matching-files-allow-populated",
			src:  frontend, dst: backend,
			traffic: Traffic{Port: 8080, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("allow-1", "default", map[string]string{"app": "backend"},
					[]v1.NetworkPolicyIngressRule{npIng([]v1.NetworkPolicyPeer{npPodSel(map[string]string{"app": "frontend"})}, []v1.NetworkPolicyPort{npPort("TCP", 8080)})},
					nil),
			},
			wantIng:   VerdictAllow,
			wantFiles: []string{"allow-1.yaml"},
		},

		// --- deny: MatchingFiles contains the covering policy file ---
		{
			name: "matching-files-deny-populated",
			src:  unrelated, dst: backend,
			traffic: Traffic{Port: 8080, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("deny-1", "default", map[string]string{"app": "backend"},
					[]v1.NetworkPolicyIngressRule{npIng([]v1.NetworkPolicyPeer{npPodSel(map[string]string{"app": "frontend"})}, []v1.NetworkPolicyPort{npPort("TCP", 8080)})},
					nil),
			},
			wantIng:   VerdictDeny,
			wantFiles: []string{"deny-1.yaml"},
		},

		// --- multiple allow rules → files deduped and sorted ---
		{
			name: "matching-files-sorted-deduped",
			src:  backend, dst: backend,
			traffic: Traffic{Port: 80, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildNP("z-pol", "default", map[string]string{"app": "backend"},
					[]v1.NetworkPolicyIngressRule{npIng(nil, []v1.NetworkPolicyPort{npPort("TCP", 80)})},
					nil),
				buildNP("a-pol", "default", map[string]string{"app": "backend"},
					[]v1.NetworkPolicyIngressRule{npIng(nil, []v1.NetworkPolicyPort{npPort("TCP", 80)})},
					nil),
			},
			wantIng:   VerdictAllow,
			wantFiles: []string{"a-pol.yaml", "z-pol.yaml"},
		},

		// --- undetermined → no MatchingFiles ---
		{
			name: "matching-files-undetermined-empty",
			src:  frontend, dst: backend,
			traffic:   Traffic{Port: 80, Protocol: "TCP"},
			policies:  []LoadedPolicy{},
			wantIng:   VerdictUndetermined,
			wantEgr:   VerdictUndetermined,
			wantFiles: nil,
		},
	}

	// Load real fixture-based policies separately to avoid init-time complications.
	fixturePolicies := []struct {
		fileName  string
		src, dst  Endpoint
		traffic   Traffic
		wantIng   Verdict
		wantEgr   Verdict
		wantFiles []string
	}{
		{
			fileName: "allow-ingress-np.yaml",
			src:      frontend, dst: backend,
			traffic:   Traffic{Port: 8080, Protocol: "TCP"},
			wantIng:   VerdictAllow,
			wantFiles: []string{"allow-ingress-np.yaml"},
		},
		{
			fileName: "deny-ingress-np.yaml",
			src:      frontend, dst: backend,
			traffic:   Traffic{Port: 8080, Protocol: "TCP"},
			wantIng:   VerdictDeny,
			wantFiles: []string{"deny-ingress-np.yaml"},
		},
		{
			fileName: "allow-ingress-np.yaml",
			// Policy covers dst (backend, ns=default); same-ns peer app=frontend fails for src in "other" ns → DENY
			src:       Endpoint{Namespace: "other", Labels: map[string]string{"app": "frontend"}},
			dst:       backend,
			traffic:   Traffic{Port: 8080, Protocol: "TCP"},
			wantIng:   VerdictDeny,
			wantFiles: []string{"allow-ingress-np.yaml"},
		},
	}

	for _, tc := range fixturePolicies {
		tc := tc
		t.Run(tc.fileName, func(t *testing.T) {
			t.Parallel()
			pols, _, err := LoadPolicies(npFixtureDir)
			if err != nil {
				t.Fatalf("LoadPolicies: %v", err)
			}
			if pols == nil {
				pols = []LoadedPolicy{}
			}
			// Filter to only the specific fixture policy under test.
			var filtered []LoadedPolicy
			for _, p := range pols {
				if p.File == tc.fileName {
					filtered = append(filtered, p)
				}
			}
			if filtered == nil {
				filtered = []LoadedPolicy{}
			}
			result := EvaluateNetworkPolicy(tc.src, tc.dst, tc.traffic, filtered)
			if tc.wantIng != "" {
				npCheck(t, "ingress", tc.wantIng, result.Ingress)
			}
			if tc.wantEgr != "" {
				npCheck(t, "egress", tc.wantEgr, result.Egress)
			}
			if len(tc.wantFiles) > 0 {
				if len(tc.wantFiles) != len(result.MatchingFiles) {
					t.Errorf("file count: got %d; want %d for ingress=%s files=%v",
						len(result.MatchingFiles), len(tc.wantFiles),
						result.Ingress, result.MatchingFiles)
				}
				for _, wf := range tc.wantFiles {
					found := false
					for _, mf := range result.MatchingFiles {
						if mf == wf {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Missing file %q in MatchingFiles: %v", wf, result.MatchingFiles)
					}
				}
			}
		})
	}

	// Run inline tests.
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := EvaluateNetworkPolicy(tt.src, tt.dst, tt.traffic, tt.policies)
			if tt.wantIng != "" {
				npCheck(t, "ingress", tt.wantIng, result.Ingress)
			}
			if tt.wantEgr != "" {
				npCheck(t, "egress", tt.wantEgr, result.Egress)
			}
			if !reflect.DeepEqual(tt.wantFiles, result.MatchingFiles) {
				t.Errorf("files: got %v; want %v", result.MatchingFiles, tt.wantFiles)
			}
		})
	}
}

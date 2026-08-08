package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/flowguarder/flowguarder/pkg/analyze"
	"github.com/flowguarder/flowguarder/pkg/anomaly"
	"github.com/flowguarder/flowguarder/pkg/policy"
)

// TestReview6 asserts the REVIEW6 acceptance criteria against the
// flowlab/hubble-flows-before.jsonl fixture:
//
//	(a) kube-dns ingress: ports 8080/TCP and 8181/TCP from 10.244.0.57/32
//	(b) kube-dns egress:  6443/TCP to 192.168.107.5/32
//	(c) local-path-provisioner egress: 6443/TCP to 192.168.107.5/32
//	(d) hubble-relay egress: 4244/TCP to 192.168.107.5/32 AND 192.168.107.4/32
//	(e) hubble-relay egress 4244/TCP: NO spurious 10.244.0.57/32
//	(f) no illegal selector keys in any generated YAML
func TestReview6(t *testing.T) {
	t.Parallel()

	flows := loadFixture(t)
	cfg := loadTestConfig()
	cfg.APIServerCIDRs = configIPNetSlice(analyze.InferAPIServerCIDRs(flows, cfg))
	flows2 := analyze.Classify(flows, cfg)
	workloads := analyze.Aggregate(flows2)
	patterns := analyze.ComputePatterns(flows2, workloads)
	anomalies := anomaly.RunAll(flows2, patterns, workloads, cfg)
	pols := policy.Build(flows2, patterns, workloads, anomalies, policy.BuildOptions{
		Config: &cfg,
	})
	if len(pols) == 0 {
		t.Fatal("no policies built from fixture")
	}

	// Locate the three target workloads by fuzzy ID match (mirrors
	// review5_test.go's matching style — never hardcode exact IDs).
	var corednsPol, provisionerPol, relayPol *policy.Policy
	for i := range pols {
		p := &pols[i]
		lower := strings.ToLower(p.WorkloadID)
		switch {
		case strings.Contains(lower, "kube-dns") || strings.Contains(lower, "coredns"):
			corednsPol = &pols[i]
		case strings.Contains(lower, "local-path"):
			provisionerPol = &pols[i]
		case strings.Contains(lower, "hubble-relay"):
			relayPol = &pols[i]
		}
	}
	if corednsPol == nil {
		t.Fatal("no kube-dns policy found")
	}
	if provisionerPol == nil {
		t.Fatal("no local-path-provisioner policy found")
	}
	if relayPol == nil {
		t.Fatal("no hubble-relay policy found")
	}

	// --- (a) kube-dns ingress: 8080/TCP + 8181/TCP from 10.244.0.57/32 ---
	npCoredns := buildNetworkPolicy(*corednsPol, cfg, workloads)
	portsByCIDR := map[string][]string{}
	for _, rule := range npCoredns.Spec.Ingress {
		for _, c := range extractCIDRs(rule.From) {
			portsByCIDR[c] = append(portsByCIDR[c], portStrings(rule.Ports)...)
		}
	}
	has := func(slice []string, want string) bool {
		for _, s := range slice {
			if s == want {
				return true
			}
		}
		return false
	}
	ps := portsByCIDR["10.244.0.57/32"]
	if len(ps) == 0 {
		t.Errorf("REVIEW6 (a): kube-dns ingress missing CIDR 10.244.0.57/32 (have: %v)", cidrKeys(portsByCIDR))
	}
	if !has(ps, "8080/TCP") {
		t.Errorf("REVIEW6 (a): kube-dns ingress from 10.244.0.57/32 missing port 8080/TCP (have: %v)", ps)
	}
	if !has(ps, "8181/TCP") {
		t.Errorf("REVIEW6 (a): kube-dns ingress from 10.244.0.57/32 missing port 8181/TCP (have: %v)", ps)
	}

	// --- (b) kube-dns egress: 6443/TCP to 192.168.107.5/32 ---
	if !egressHas(npCoredns.Spec.Egress, "6443/TCP", "192.168.107.5/32") {
		t.Errorf("REVIEW6 (b): kube-dns egress missing 6443/TCP -> 192.168.107.5/32")
	}

	// --- (c) provisioner egress: 6443/TCP to 192.168.107.5/32 ---
	npProv := buildNetworkPolicy(*provisionerPol, cfg, workloads)
	if !egressHas(npProv.Spec.Egress, "6443/TCP", "192.168.107.5/32") {
		t.Errorf("REVIEW6 (c): local-path-provisioner egress missing 6443/TCP -> 192.168.107.5/32")
	}

	// --- (d) + (e) hubble-relay egress 4244/TCP ---
	npRelay := buildNetworkPolicy(*relayPol, cfg, workloads)
	relayCIDRs := egressCIDRsForPort(npRelay.Spec.Egress, "4244/TCP")
	if !has(relayCIDRs, "192.168.107.5/32") {
		t.Errorf("REVIEW6 (d): hubble-relay egress 4244/TCP missing 192.168.107.5/32 (have: %v)", relayCIDRs)
	}
	if !has(relayCIDRs, "192.168.107.4/32") {
		t.Errorf("REVIEW6 (d): hubble-relay egress 4244/TCP missing 192.168.107.4/32 (have: %v)", relayCIDRs)
	}
	if has(relayCIDRs, "10.244.0.57/32") {
		t.Errorf("REVIEW6 (e): hubble-relay egress 4244/TCP has spurious 10.244.0.57/32 (have: %v)", relayCIDRs)
	}

	// --- (f) no illegal selector keys in generated YAML ---
	tmpDir := t.TempDir()
	for _, p := range pols {
		writePolicyYAML(tmpDir, p, cfg, workloads)
	}
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(tmpDir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if err := checkNoIllegalYAMLKeys(data); err != nil {
			t.Errorf("REVIEW6 (f) %s: %v", e.Name(), err)
		}
	}
}

// portStrings renders NetworkPolicyPort entries as "port/protocol".
func portStrings(ports []networkingv1.NetworkPolicyPort) []string {
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		if p.Port == nil {
			continue
		}
		var pt string
		if p.Port.Type == intstr.Int {
			pt = strconv.Itoa(int(p.Port.IntVal))
		} else {
			pt = p.Port.StrVal
		}
		if p.Protocol != nil {
			pt += "/" + string(*p.Protocol)
		}
		out = append(out, pt)
	}
	return out
}

// egressHas reports whether any egress rule has the given port/protocol and
// the given CIDR among its To IPBlocks.
func egressHas(rules []networkingv1.NetworkPolicyEgressRule, port, cidr string) bool {
	for _, rule := range rules {
		if !hasString(portStrings(rule.Ports), port) {
			continue
		}
		if hasString(extractCIDRs(rule.To), cidr) {
			return true
		}
	}
	return false
}

// egressCIDRsForPort returns the union of To IPBlock CIDRs across all egress
// rules that carry the given port/protocol.
func egressCIDRsForPort(rules []networkingv1.NetworkPolicyEgressRule, port string) []string {
	var out []string
	for _, rule := range rules {
		if !hasString(portStrings(rule.Ports), port) {
			continue
		}
		out = append(out, extractCIDRs(rule.To)...)
	}
	return out
}

func hasString(slice []string, want string) bool {
	for _, s := range slice {
		if s == want {
			return true
		}
	}
	return false
}

func cidrKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

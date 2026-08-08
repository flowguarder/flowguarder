package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/flowguarder/flowguarder/pkg/analyze"
	"github.com/flowguarder/flowguarder/pkg/anomaly"
	"github.com/flowguarder/flowguarder/pkg/config"
	"github.com/flowguarder/flowguarder/pkg/flow"
	"github.com/flowguarder/flowguarder/pkg/parser"
	"github.com/flowguarder/flowguarder/pkg/policy"
)

// fixturePath returns the path to the flowlab fixture file,
// resolving relative to the repo root (since Go tests run from the
// package directory).  It falls back to testdata/ as a last resort.
func fixturePath() string {
	if p := filepath.Join("..", "..", "flowlab", "hubble-flows-before.jsonl"); exists(p) {
		return p
	}
	if p := "flowlab/hubble-flows-before.jsonl"; exists(p) {
		return p
	}
	if p := "testdata/hubble-flows-before.jsonl"; exists(p) {
		return p
	}
	return ""
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// loadFixture reads, parses, and returns the flowlab flows.
func loadFixture(t *testing.T) []flow.Flow {
	t.Helper()
	fp := fixturePath()
	if fp == "" {
		t.Fatalf("cannot find fixture: try flowlab/hubble-flows-before.jsonl")
	}
	fc, err := os.ReadFile(fp)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	prs, err := parser.SelectParser(parser.SourceHubble, parser.SourceAuto)
	if err != nil {
		t.Fatalf("select parser: %v", err)
	}
	var flows []flow.Flow
	r := bytes.NewReader(fc)
	err = prs.Parse(r, func(f flow.Flow) error {
		if e := f.Validate(); e == nil {
			flows = append(flows, f)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("parse flows: %v", err)
	}
	if len(flows) == 0 {
		t.Fatal("no flows parsed")
	}
	return flows
}

// loadTestConfig returns the default config with a reasonable cluster_cidrs.
func loadTestConfig() config.Config {
	return config.Default()
}

// ---------------------------------------------------------------------------
// TestReview5Policies — 4-plan-assertion E2E
// ---------------------------------------------------------------------------

// TestReview5Policies validates generated policies against the
// flowlab/hubble-flows-before.jsonl fixture for the Review5 plan:
//
//	(a) NO matchLabels key contains ":" or "io.cilium." or "io.kubernetes.pod.namespace"
//	(b) coredns scope uses k8s-app: kube-dns
//	(c) demo ingress selector: app: demo-client (NOT k8s:app)
//	(d) internal ports (8080,8181,4222,4245,6443) never paired with 0.0.0.0/0
func TestReview5Policies(t *testing.T) {
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

	// (a) — raw FromWorkload / ToWorkload must not contain "reserved:"
	for _, p := range pols {
		for _, r := range p.IngressRules {
			for _, fw := range r.FromWorkloads {
				if strings.Contains(fw, "reserved:") {
					t.Errorf("assertion (a) %s: FromWorkload %q contains reserved:", p.WorkloadID, fw)
				}
			}
		}
		for _, r := range p.EgressRules {
			for _, tw := range r.ToWorkloads {
				if strings.Contains(tw, "reserved:") {
					t.Errorf("assertion (a) %s: ToWorkload %q contains reserved:", p.WorkloadID, tw)
				}
			}
			for _, cidr := range r.ToCIDRs {
				if strings.Contains(cidr, "reserved:") {
					t.Errorf("assertion (a) %s: ToCIDR %q contains reserved:", p.WorkloadID, cidr)
				}
			}
		}
	}

	// (b), (c), (d) — inspect the built NetworkPolicy objects.
	for _, p := range pols {
		np := buildNetworkPolicy(p, cfg, workloads)
		fname := sanitizeName(np.ObjectMeta.Name) + ".yaml"

		// (b) coredns scope.
		if strings.Contains(strings.ToLower(p.WorkloadName), "kube-dns") ||
			strings.Contains(strings.ToLower(p.WorkloadName), "coredns") {
			ml := np.Spec.PodSelector.MatchLabels
			found := false
			for k, v := range ml {
				if k == "k8s-app" && v == "kube-dns" {
					found = true
				}
				if k == "app" && strings.HasPrefix(v, "coredns-") {
					t.Errorf("assertion (b) %s: uses app: %q instead of k8s-app: kube-dns", fname, v)
				}
			}
			if !found {
				t.Errorf("assertion (b) %s: missing k8s-app: kube-dns in scope selector", fname)
			}
		}

		// (c) demo-client ingress — demo-server policy should select app: demo-client.
		if p.WorkloadName == "demo-server" {
			found := false
			for _, rule := range np.Spec.Ingress {
				for _, from := range rule.From {
					if from.PodSelector == nil {
						continue
					}
					for k, v := range from.PodSelector.MatchLabels {
						if k == "k8s:app" {
							t.Errorf("assertion (c) %s: ingress uses k8s:app", fname)
						}
						if k == "app" && v == "demo-client" {
							found = true
						}
					}
				}
			}
			if !found {
				t.Errorf("assertion (c) %s: ingress missing app: demo-client", fname)
			}
		}

		// (d) internal ports never paired with 0.0.0.0/0.
		internalPorts := map[string]bool{"8080": true, "8181": true, "4222": true, "4245": true, "6443": true}
		for _, rule := range np.Spec.Ingress {
			cidrs := extractCIDRs(rule.From)
			for _, port := range rule.Ports {
				if port.Port == nil {
					continue
				}
				var pt string
				if port.Port.Type == intstr.Int {
					pt = strconv.Itoa(int(port.Port.IntVal))
				} else {
					pt = port.Port.StrVal
				}
				if _, ok := internalPorts[pt]; ok {
					for _, c := range cidrs {
						if c == "0.0.0.0/0" {
							t.Errorf("assertion (d) %s: ingress port %s paired with 0.0.0.0/0", fname, pt)
						}
					}
				}
			}
		}
		for _, rule := range np.Spec.Egress {
			cidrs := extractCIDRs(rule.To)
			for _, port := range rule.Ports {
				if port.Port == nil {
					continue
				}
				var pt string
				if port.Port.Type == intstr.Int {
					pt = strconv.Itoa(int(port.Port.IntVal))
				} else {
					pt = port.Port.StrVal
				}
				if _, ok := internalPorts[pt]; ok {
					for _, c := range cidrs {
						if c == "0.0.0.0/0" {
							t.Errorf("assertion (d) %s: egress port %s paired with 0.0.0.0/0", fname, pt)
						}
					}
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// YAML assertion helper: checkNoIllegalYAMLKeys
// ---------------------------------------------------------------------------

func TestYAMLKeys(t *testing.T) {
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

	// Write YAML to a temp dir, then re-read and assert matchLabels keys.
	tmpDir := t.TempDir()
	for _, p := range pols {
		writePolicyYAML(tmpDir, p, cfg, workloads)
	}

	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	var yamlFiles []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".yaml") {
			yamlFiles = append(yamlFiles, e.Name())
		}
	}
	for _, yf := range yamlFiles {
		data, err := os.ReadFile(filepath.Join(tmpDir, yf))
		if err != nil {
			t.Fatalf("read %s: %v", yf, err)
		}
		// Assert (a) through YAML parsing: no illegal keys in any matchLabels.
		if err := checkNoIllegalYAMLKeys(data); err != nil {
			t.Errorf("assertion (a) YAML %s: %v", yf, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Reserved-label peer tests
// ---------------------------------------------------------------------------

// TestReservedLabelNoInFromWorkloads ensures reserved-label peers never
// leak into FromWorkloads / ToWorkloads as selector strings.
func TestReservedLabelNoInFromWorkloads(t *testing.T) {
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

	for _, p := range pols {
		t.Run(p.WorkloadID, func(t *testing.T) {
			t.Parallel()
			for _, r := range p.IngressRules {
				for _, fw := range r.FromWorkloads {
					if strings.HasPrefix(fw, "reserved:") {
						t.Errorf("ingress FromWorkload: %q", fw)
					}
				}
			}
			for _, r := range p.EgressRules {
				for _, fw := range r.ToWorkloads {
					if strings.HasPrefix(fw, "reserved:") {
						t.Errorf("egress ToWorkload: %q", fw)
					}
				}
				for _, cidr := range r.ToCIDRs {
					if strings.HasPrefix(cidr, "reserved:") {
						t.Errorf("egress ToCIDR: %q", cidr)
					}
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// extractCIDRs returns all IPBlock CIDRs from a slice of peers.
func extractCIDRs(peers []networkingv1.NetworkPolicyPeer) []string {
	var cidrs []string
	for _, p := range peers {
		if p.IPBlock != nil {
			cidrs = append(cidrs, p.IPBlock.CIDR)
		}
	}
	return cidrs
}

// checkNoIllegalYAMLKeys parses the YAML output for a policy and ensures
// every matchLabels mapping has legal keys (no ":" , "io.cilium.", etc.).
func checkNoIllegalYAMLKeys(data []byte) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			break
		}
		if err := walkNode(&doc); err != nil {
			return err
		}
	}
	return nil
}

func walkNode(n *yaml.Node) error {
	if n == nil {
		return nil
	}

	// Mapping: iterate ALL children, recurse into every value.
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			key := n.Content[i].Value
			// Check matchLabels value.
			if key == "matchLabels" && n.Content[i+1].Kind == yaml.MappingNode {
				ml := n.Content[i+1]
				for j := 0; j+1 < len(ml.Content); j += 2 {
					k := ml.Content[j].Value
					if strings.Contains(k, ":") {
						return &illegalKeyError{k: k}
					}
					if strings.HasPrefix(k, "io.cilium.") {
						return &illegalKeyError{k: k}
					}
					if k == "io.kubernetes.pod.namespace" {
						return &illegalKeyError{k: k}
					}
				}
			}
			// Recurse into the value.
			if err := walkNode(n.Content[i+1]); err != nil {
				return err
			}
		}
		return nil
	}

	// Sequence: recurse into every element.
	if n.Kind == yaml.SequenceNode {
		for _, c := range n.Content {
			if err := walkNode(c); err != nil {
				return err
			}
		}
	}
	return nil
}

type illegalKeyError struct{ k string }

func (e *illegalKeyError) Error() string {
	return "illegal selector key: " + e.k
}

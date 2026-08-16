package simulate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/flowguarder/flowguarder/pkg/policy"
)

// testFixtureDir is relative to pkg/simulate/loader_test.go → ../../testdata/simulate.
const testFixtureDir = "../../testdata/simulate"

func mustFixture(name string) []byte {
	b, err := os.ReadFile(filepath.Join(testFixtureDir, name))
	if err != nil {
		panic("read fixture " + name + ": " + err.Error())
	}
	return b
}

// ---------------------------------------------------------------------------
// Test helpers: build an inline CNP.
// ---------------------------------------------------------------------------

func buildIN(name, ns string, sel map[string]string,
	ingress []policy.CNPIngressRule,
	egress []policy.CNPEgressRule,
) LoadedPolicy {
	if ns == "" {
		ns = "default"
	}
	return LoadedPolicy{
		File: name + ".yaml",
		Kind: "CiliumNetworkPolicy",
		Cilium: &policy.CiliumNetworkPolicy{
			APIVersion: "cilium.io/v2",
			Kind:       "CiliumNetworkPolicy",
			Metadata: policy.CNPMetadata{
				Name:      name,
				Namespace: ns,
			},
			Spec: policy.CNPSpec{
				EndpointSelector: policy.CNPEntitySelector{
					MatchLabels: sel,
				},
				Ingress: ingress,
				Egress:  egress,
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Pre-built fixtures matching YAML fixtures in testdata/simulate/.
// ---------------------------------------------------------------------------

var fixtureAllowEgress = &policy.CiliumNetworkPolicy{
	APIVersion: "cilium.io/v2",
	Kind:       "CiliumNetworkPolicy",
	Metadata:   policy.CNPMetadata{Name: "allow-egress", Namespace: "default"},
	Spec: policy.CNPSpec{
		EndpointSelector: policy.CNPEntitySelector{MatchLabels: map[string]string{"app": "frontend"}},
		Egress: []policy.CNPEgressRule{
			{
				ToEndpoints: []policy.CNPEntitySelector{{MatchLabels: map[string]string{"app": "backend"}}},
				ToPorts:     []policy.CNPToPorts{{Ports: []policy.PortRule{{Port: "8080", Protocol: "TCP"}}}},
			},
		},
	},
}

var fixtureDenyEgress = &policy.CiliumNetworkPolicy{
	APIVersion: "cilium.io/v2",
	Kind:       "CiliumNetworkPolicy",
	Metadata:   policy.CNPMetadata{Name: "deny-egress", Namespace: "default"},
	Spec: policy.CNPSpec{
		EndpointSelector: policy.CNPEntitySelector{MatchLabels: map[string]string{"app": "frontend"}},
		Egress: []policy.CNPEgressRule{
			{
				ToEndpoints: []policy.CNPEntitySelector{{MatchLabels: map[string]string{"app": "unrelated"}}},
				ToPorts:     []policy.CNPToPorts{{Ports: []policy.PortRule{{Port: "8080", Protocol: "TCP"}}}},
			},
		},
	},
}

var fixtureDNSAllow = &policy.CiliumNetworkPolicy{
	APIVersion: "cilium.io/v2",
	Kind:       "CiliumNetworkPolicy",
	Metadata:   policy.CNPMetadata{Name: "dns-allow", Namespace: "default"},
	Spec: policy.CNPSpec{
		EndpointSelector: policy.CNPEntitySelector{MatchLabels: map[string]string{"app": "frontend"}},
		Egress: []policy.CNPEgressRule{
			{
				ToFQDNs: []policy.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []policy.CNPToPorts{
					{
						Ports: []policy.PortRule{{Port: "53", Protocol: "UDP"}},
						Rules: &policy.CNPRules{
							DNS: []policy.CNPDNSRule{{MatchName: "example.com"}},
						},
					},
				},
			},
		},
	},
}

// ---------------------------------------------------------------------------
// Table-driven tests.
// ---------------------------------------------------------------------------

func TestEvaluateCiliumNetworkPolicy(t *testing.T) {
	t.Parallel()

	frontend := Endpoint{Namespace: "default", Labels: map[string]string{"app": "frontend"}}
	backend := Endpoint{Namespace: "default", Labels: map[string]string{"app": "backend"}}
	unrelated := Endpoint{Namespace: "default", Labels: map[string]string{"app": "unrelated"}}

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
		{
			name:    "fixture-egress-allow-toEndpoints-match",
			src:     frontend,
			dst:     backend,
			traffic: Traffic{Port: 8080, Protocol: "TCP"},
			policies: []LoadedPolicy{
				{File: "allow-egress-cnp.yaml", Kind: "CiliumNetworkPolicy", Cilium: fixtureAllowEgress},
			},
			wantIng:   VerdictUndetermined,
			wantEgr:   VerdictAllow,
			wantFiles: []string{"allow-egress-cnp.yaml"},
		},
		{
			name:    "fixture-egress-deny-toEndpoints-mismatch",
			src:     frontend,
			dst:     Endpoint{Namespace: "default", Labels: map[string]string{"app": "backend"}},
			traffic: Traffic{Port: 8080, Protocol: "TCP"},
			policies: []LoadedPolicy{
				{File: "deny-egress-cnp.yaml", Kind: "CiliumNetworkPolicy", Cilium: fixtureDenyEgress},
			},
			wantIng:   VerdictUndetermined,
			wantEgr:   VerdictDeny,
			wantFiles: []string{"deny-egress-cnp.yaml"},
		},

		{
			name:    "egress-endpointSelector-mismatch",
			src:     Endpoint{Namespace: "default"},
			dst:     frontend,
			traffic: Traffic{Port: 8080, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildIN("no-match", "default", map[string]string{"app": "backend"}, nil, nil),
			},
			wantEgr: VerdictUndetermined,
		},
		{
			name:    "egress-endpointSelector-nil-select-all",
			src:     backend,
			dst:     frontend,
			traffic: Traffic{Port: 8080, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildIN("all-select", "default", nil, nil, []policy.CNPEgressRule{
					{ToPorts: []policy.CNPToPorts{{Ports: []policy.PortRule{{Port: "8080", Protocol: "TCP"}}}}},
				}),
			},
			wantEgr:   VerdictAllow,
			wantFiles: []string{"all-select.yaml"},
		},

		{
			name:    "ingress-fromEndpoints-match",
			src:     frontend,
			dst:     backend,
			traffic: Traffic{Port: 8080, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildIN("ingress-fe", "default", map[string]string{"app": "backend"}, []policy.CNPIngressRule{
					{FromEndpoints: []policy.CNPEntitySelector{{MatchLabels: map[string]string{"app": "frontend"}}}},
				}, nil),
			},
			wantIng:   VerdictAllow,
			wantFiles: []string{"ingress-fe.yaml"},
		},
		{
			name:    "ingress-fromEndpoints-mismatch",
			src:     unrelated,
			dst:     backend,
			traffic: Traffic{Port: 8080, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildIN("ingress-fe", "default", map[string]string{"app": "backend"}, []policy.CNPIngressRule{
					{FromEndpoints: []policy.CNPEntitySelector{{MatchLabels: map[string]string{"app": "frontend"}}}},
				}, nil),
			},
			wantIng:   VerdictDeny,
			wantFiles: []string{"ingress-fe.yaml"},
		},

		{
			name:    "egress-toEntities-world-match",
			src:     frontend,
			dst:     Endpoint{Namespace: "default", Entity: "world"},
			traffic: Traffic{Port: 443, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildIN("egress-world", "default", map[string]string{"app": "frontend"}, nil, []policy.CNPEgressRule{
					{ToEntities: []string{"world"}, ToPorts: []policy.CNPToPorts{{Ports: []policy.PortRule{{Port: "443", Protocol: "TCP"}}}}},
				}),
			},
			wantEgr:   VerdictAllow,
			wantFiles: []string{"egress-world.yaml"},
		},
		{
			name:    "egress-toEntities-cluster-match",
			src:     frontend,
			dst:     Endpoint{Namespace: "default", Entity: "cluster"},
			traffic: Traffic{Port: 80, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildIN("egress-cl", "default", map[string]string{"app": "frontend"}, nil, []policy.CNPEgressRule{
					{ToEntities: []string{"cluster"}, ToPorts: []policy.CNPToPorts{{Ports: []policy.PortRule{{Port: "80", Protocol: "TCP"}}}}},
				}),
			},
			wantEgr:   VerdictAllow,
			wantFiles: []string{"egress-cl.yaml"},
		},
		{
			name:    "egress-toEntities-no-match",
			src:     frontend,
			dst:     Endpoint{Namespace: "default", Entity: "world"},
			traffic: Traffic{Port: 443, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildIN("egress-host", "default", map[string]string{"app": "frontend"}, nil, []policy.CNPEgressRule{
					{ToEntities: []string{"host"}, ToPorts: []policy.CNPToPorts{{Ports: []policy.PortRule{{Port: "443", Protocol: "TCP"}}}}},
				}),
			},
			wantEgr:   VerdictDeny,
			wantFiles: []string{"egress-host.yaml"},
		},

		{
			name:    "egress-toCIDR-match",
			src:     frontend,
			dst:     Endpoint{Namespace: "default", IP: "203.0.113.5"},
			traffic: Traffic{Port: 80, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildIN("egress-cidr", "default", map[string]string{"app": "frontend"}, nil, []policy.CNPEgressRule{
					{ToCIDR: []string{"203.0.113.0/24"}, ToPorts: []policy.CNPToPorts{{Ports: []policy.PortRule{{Port: "80", Protocol: "TCP"}}}}},
				}),
			},
			wantEgr:   VerdictAllow,
			wantFiles: []string{"egress-cidr.yaml"},
		},
		{
			name:    "egress-toCIDR-no-match",
			src:     frontend,
			dst:     Endpoint{Namespace: "default", IP: "198.51.100.5"},
			traffic: Traffic{Port: 80, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildIN("egress-cidr", "default", map[string]string{"app": "frontend"}, nil, []policy.CNPEgressRule{
					{ToCIDR: []string{"203.0.113.0/24"}, ToPorts: []policy.CNPToPorts{{Ports: []policy.PortRule{{Port: "80", Protocol: "TCP"}}}}},
				}),
			},
			wantEgr:   VerdictDeny,
			wantFiles: []string{"egress-cidr.yaml"},
		},
		{
			name:    "egress-toCIDR-no-src-ip",
			src:     Endpoint{Namespace: "default"},
			dst:     frontend,
			traffic: Traffic{Port: 80, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildIN("ingress-cidr", "default", map[string]string{"app": "frontend"}, []policy.CNPIngressRule{
					{FromCIDR: []string{"10.0.0.0/8"}},
				}, nil),
			},
			wantIng:   VerdictDeny,
			wantFiles: []string{"ingress-cidr.yaml"},
		},

		{
			name:    "egress-ports-match",
			src:     frontend,
			dst:     backend,
			traffic: Traffic{Port: 8080, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildIN("ports-match", "default", map[string]string{"app": "frontend"}, nil, []policy.CNPEgressRule{
					{ToPorts: []policy.CNPToPorts{{Ports: []policy.PortRule{{Port: "8080", Protocol: "TCP"}}}}},
				}),
			},
			wantEgr:   VerdictAllow,
			wantFiles: []string{"ports-match.yaml"},
		},
		{
			name:    "egress-ports-protocol-mismatch",
			src:     frontend,
			dst:     backend,
			traffic: Traffic{Port: 8080, Protocol: "UDP"},
			policies: []LoadedPolicy{
				buildIN("ports-proto", "default", map[string]string{"app": "frontend"}, nil, []policy.CNPEgressRule{
					{ToPorts: []policy.CNPToPorts{{Ports: []policy.PortRule{{Port: "8080", Protocol: "TCP"}}}}},
				}),
			},
			wantEgr:   VerdictDeny,
			wantFiles: []string{"ports-proto.yaml"},
		},
		{
			name:    "egress-ports-port-mismatch",
			src:     frontend,
			dst:     backend,
			traffic: Traffic{Port: 80, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildIN("ports-port", "default", map[string]string{"app": "frontend"}, nil, []policy.CNPEgressRule{
					{ToPorts: []policy.CNPToPorts{{Ports: []policy.PortRule{{Port: "8080", Protocol: "TCP"}}}}},
				}),
			},
			wantEgr:   VerdictDeny,
			wantFiles: []string{"ports-port.yaml"},
		},
		{
			name:    "egress-ports-empty-port-any",
			src:     frontend,
			dst:     backend,
			traffic: Traffic{Port: 9999, Protocol: "UDP"},
			policies: []LoadedPolicy{
				buildIN("ports-any", "default", map[string]string{"app": "frontend"}, nil, []policy.CNPEgressRule{
					{ToPorts: []policy.CNPToPorts{{Ports: []policy.PortRule{{Port: "", Protocol: "UDP"}}}}},
				}),
			},
			wantEgr:   VerdictAllow,
			wantFiles: []string{"ports-any.yaml"},
		},
		{
			name:    "egress-port-0-any-port",
			src:     frontend,
			dst:     backend,
			traffic: Traffic{Port: 0, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildIN("port-any", "default", map[string]string{"app": "frontend"}, nil, []policy.CNPEgressRule{
					{ToPorts: []policy.CNPToPorts{{Ports: []policy.PortRule{{Port: "443", Protocol: "TCP"}}}}},
				}),
			},
			wantEgr:   VerdictAllow,
			wantFiles: []string{"port-any.yaml"},
		},

		// Default-deny: toEntities mismatch → covered but no match.
		{
			name:    "egress-default-deny-toEntities",
			src:     Endpoint{Namespace: "default", Labels: map[string]string{"app": "frontend"}},
			dst:     Endpoint{Namespace: "default", Entity: "unknown"},
			traffic: Traffic{Port: 80, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildIN("deny-entities", "default", map[string]string{"app": "frontend"}, nil, []policy.CNPEgressRule{
					{ToEntities: []string{"world"}, ToPorts: []policy.CNPToPorts{{Ports: []policy.PortRule{{Port: "80", Protocol: "TCP"}}}}},
				}),
			},
			wantEgr:   VerdictDeny,
			wantFiles: []string{"deny-entities.yaml"},
		},

		// Empty egress list (non-nil) with no matching rules on scope endpoint → covered → deny.
		{
			name:    "egress-default-deny-empty-rule-list",
			src:     frontend,
			dst:     Endpoint{Namespace: "default", Entity: "unknown"},
			traffic: Traffic{Port: 80, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildIN("deny-all", "default", map[string]string{"app": "frontend"}, nil, []policy.CNPEgressRule{
					{ToEntities: []string{"world"}}, // has constraints (toEntities) but entity doesn't match
				}),
			},
			wantEgr:   VerdictDeny,
			wantFiles: []string{"deny-all.yaml"},
		},
		{
			name:    "egress-undetermined-no-egress",
			src:     frontend,
			dst:     backend,
			traffic: Traffic{Port: 80, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildIN("no-egress", "default", map[string]string{"app": "frontend"}, nil, nil),
			},
			wantEgr: VerdictUndetermined,
		},

		// No constraint rule = allow all.
		{
			name:    "ingress-no-constraints-allow",
			src:     unrelated,
			dst:     backend,
			traffic: Traffic{Port: 9999, Protocol: "UDP"},
			policies: []LoadedPolicy{
				buildIN("allow-all", "default", map[string]string{"app": "backend"}, []policy.CNPIngressRule{
					{}, // empty rule = no constraints
				}, nil),
			},
			wantIng:   VerdictAllow,
			wantFiles: []string{"allow-all.yaml"},
		},

		// DNS via fixture: dns-allow-cnp.yaml.
		{
			name:    "dns-allow-exact-match",
			src:     Endpoint{Namespace: "default", Labels: map[string]string{"app": "frontend"}},
			dst:     Endpoint{Namespace: "default", Labels: map[string]string{"app": "backend"}},
			traffic: Traffic{Port: 53, Protocol: "UDP", L7Name: "example.com"},
			policies: []LoadedPolicy{
				{File: "dns-allow-cnp.yaml", Kind: "CiliumNetworkPolicy", Cilium: fixtureDNSAllow},
			},
			wantEgr:   VerdictAllow,
			wantFiles: []string{"dns-allow-cnp.yaml"},
		},
		{
			name:    "dns-deny-wrong-l7name",
			src:     Endpoint{Namespace: "default", Labels: map[string]string{"app": "frontend"}},
			dst:     Endpoint{Namespace: "default", Labels: map[string]string{"app": "backend"}},
			traffic: Traffic{Port: 53, Protocol: "UDP", L7Name: "other.com"},
			policies: []LoadedPolicy{
				{File: "dns-allow-cnp.yaml", Kind: "CiliumNetworkPolicy", Cilium: fixtureDNSAllow},
			},
			wantEgr:   VerdictDeny,
			wantFiles: []string{"dns-allow-cnp.yaml"},
		},
		{
			name:    "dns-deny-no-fqdn-match",
			src:     Endpoint{Namespace: "default", Labels: map[string]string{"app": "frontend"}},
			dst:     Endpoint{Namespace: "default", Labels: map[string]string{"app": "backend"}},
			traffic: Traffic{Port: 53, Protocol: "UDP", L7Name: "nonexistent.org"},
			policies: []LoadedPolicy{
				{File: "dns-allow-cnp.yaml", Kind: "CiliumNetworkPolicy", Cilium: fixtureDNSAllow},
			},
			wantEgr:   VerdictDeny,
			wantFiles: []string{"dns-allow-cnp.yaml"},
		},

		// matchPattern wildcard in FQDN and DNS rules.
		{
			name:    "dns-fqdn-matchPattern-wildcard-allow",
			src:     Endpoint{Namespace: "default", Labels: map[string]string{"app": "frontend"}},
			dst:     Endpoint{Namespace: "default", Labels: map[string]string{"app": "backend"}},
			traffic: Traffic{Port: 53, Protocol: "UDP", L7Name: "api.example.com"},
			policies: []LoadedPolicy{
				{File: "wildcard-fqdn.yaml", Kind: "CiliumNetworkPolicy", Cilium: buildCNPInline(
					"wildcard-fqdn", map[string]string{"app": "frontend"}, nil, []policy.CNPEgressRule{
						{
							ToFQDNs: []policy.FQDNSelector{{MatchPattern: "*.example.com"}},
							ToPorts: []policy.CNPToPorts{
								{Ports: []policy.PortRule{{Port: "53", Protocol: "UDP"}}, Rules: &policy.CNPRules{DNS: []policy.CNPDNSRule{{MatchPattern: "*.example.com"}}}},
							},
						},
					}),
				}},
			wantEgr:   VerdictAllow,
			wantFiles: []string{"wildcard-fqdn.yaml"},
		},
		{
			name:    "dns-fqdn-matchPattern-wildcard-deny",
			src:     Endpoint{Namespace: "default", Labels: map[string]string{"app": "frontend"}},
			dst:     Endpoint{Namespace: "default", Labels: map[string]string{"app": "backend"}},
			traffic: Traffic{Port: 53, Protocol: "UDP", L7Name: "bad.not-example.com"},
			policies: []LoadedPolicy{
				{File: "wildcard-fqdn.yaml", Kind: "CiliumNetworkPolicy", Cilium: buildCNPInline(
					"wildcard-fqdn", map[string]string{"app": "frontend"}, nil, []policy.CNPEgressRule{
						{
							ToFQDNs: []policy.FQDNSelector{{MatchPattern: "*.example.com"}},
							ToPorts: []policy.CNPToPorts{
								{Ports: []policy.PortRule{{Port: "53", Protocol: "UDP"}}, Rules: &policy.CNPRules{DNS: []policy.CNPDNSRule{{MatchPattern: "*.example.com"}}}},
							},
						},
					}),
				}},
			wantEgr:   VerdictDeny,
			wantFiles: []string{"wildcard-fqdn.yaml"},
		},

		// l7 override beats traffic fields.
		{
			name:    "l7-override-beats-traffic",
			src:     Endpoint{Namespace: "default", Labels: map[string]string{"app": "frontend"}},
			dst:     Endpoint{Namespace: "default", Labels: map[string]string{"app": "backend"}},
			traffic: Traffic{Port: 53, Protocol: "UDP", L7Name: "other.com"},
			l7:      &Traffic{L7Name: "example.com"},
			policies: []LoadedPolicy{
				{File: "dns-allow-cnp.yaml", Kind: "CiliumNetworkPolicy", Cilium: fixtureDNSAllow},
			},
			wantEgr:   VerdictAllow,
			wantFiles: []string{"dns-allow-cnp.yaml"},
		},

		// Namespace scoping.
		{
			name:    "egress-namespace-scope-mismatch",
			src:     Endpoint{Namespace: "production", Labels: map[string]string{"app": "frontend"}},
			dst:     Endpoint{Namespace: "production", Labels: map[string]string{"app": "backend"}},
			traffic: Traffic{Port: 8080, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildIN("other-ns", "default", map[string]string{"app": "frontend"}, nil, []policy.CNPEgressRule{
					{ToPorts: []policy.CNPToPorts{{Ports: []policy.PortRule{{Port: "8080", Protocol: "TCP"}}}}},
				}),
			},
			wantEgr: VerdictUndetermined,
		},

		// MatchingFiles sorted+deduped.
		{
			name:    "matching-files-sorted-deduped",
			src:     frontend,
			dst:     backend,
			traffic: Traffic{Port: 80, Protocol: "TCP"},
			policies: []LoadedPolicy{
				buildIN("b-file", "default", map[string]string{"app": "backend"}, []policy.CNPIngressRule{
					{ToPorts: []policy.CNPToPorts{{Ports: []policy.PortRule{{Port: "80", Protocol: "TCP"}}}}},
				}, nil),
				buildIN("a-file", "default", map[string]string{"app": "backend"}, []policy.CNPIngressRule{
					{ToPorts: []policy.CNPToPorts{{Ports: []policy.PortRule{{Port: "80", Protocol: "TCP"}}}}},
				}, nil),
			},
			wantIng:   VerdictAllow,
			wantFiles: []string{"a-file.yaml", "b-file.yaml"},
		},

		// Empty policies.
		{
			name:     "empty-policies",
			src:      frontend,
			dst:      backend,
			traffic:  Traffic{Port: 80, Protocol: "TCP"},
			policies: []LoadedPolicy{},
			wantIng:  VerdictUndetermined,
			wantEgr:  VerdictUndetermined,
		},

		// Non-CNP policies ignored.
		{
			name:    "non-cnp-policies-ignored",
			src:     frontend,
			dst:     backend,
			traffic: Traffic{Port: 80, Protocol: "TCP"},
			policies: []LoadedPolicy{
				{File: "np.yaml", Kind: "NetworkPolicy"},
			},
			wantIng: VerdictUndetermined,
			wantEgr: VerdictUndetermined,
		},

		// Protocol case insensitive.
		{
			name:    "ports-protocol-case-insensitive",
			src:     frontend,
			dst:     backend,
			traffic: Traffic{Port: 80, Protocol: "tcp"},
			policies: []LoadedPolicy{
				buildIN("case-test", "default", map[string]string{"app": "frontend"}, nil, []policy.CNPEgressRule{
					{ToPorts: []policy.CNPToPorts{{Ports: []policy.PortRule{{Port: "80", Protocol: "TCP"}}}}},
				}),
			},
			wantEgr:   VerdictAllow,
			wantFiles: []string{"case-test.yaml"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := EvaluateCiliumNetworkPolicy(tt.src, tt.dst, tt.traffic, tt.policies, tt.l7)
			if tt.wantIng != "" {
				check(t, "ingress", tt.wantIng, got.Ingress)
			}
			if tt.wantEgr != "" {
				check(t, "egress", tt.wantEgr, got.Egress)
			}
			if tt.wantFiles != nil {
				checkSlice(t, "files", tt.wantFiles, got.MatchingFiles)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Additional edge-case tests (not fitting table pattern).
// ---------------------------------------------------------------------------

func TestEvaluateCiliumNetworkPolicy_DNSUDPAndTCP(t *testing.T) {
	t.Parallel()

	frontend := Endpoint{Namespace: "default", Labels: map[string]string{"app": "frontend"}}

	dnsCNP := buildCNPInline("dns-tcp", map[string]string{"app": "frontend"}, nil, []policy.CNPEgressRule{
		{
			ToFQDNs: []policy.FQDNSelector{{MatchName: "example.com"}},
			ToPorts: []policy.CNPToPorts{
				{Ports: []policy.PortRule{{Port: "53", Protocol: "TCP"}}, Rules: &policy.CNPRules{DNS: []policy.CNPDNSRule{{MatchName: "example.com"}}}},
			},
		},
	})

	result := EvaluateCiliumNetworkPolicy(
		frontend,
		Endpoint{Namespace: "default"},
		Traffic{Port: 53, Protocol: "TCP", L7Name: "example.com"},
		[]LoadedPolicy{{File: "dns-tcp.yaml", Kind: "CiliumNetworkPolicy", Cilium: dnsCNP}},
		nil,
	)
	if result.Egress != VerdictAllow {
		t.Fatalf("expected allow for DNS/TCP; got %s", result.Egress)
	}
	if len(result.MatchingFiles) == 0 {
		t.Fatal("expected non-empty MatchingFiles for allow")
	}
}

func TestEvaluateCiliumNetworkPolicy_FQDNNoL7NoConstrain(t *testing.T) {
	t.Parallel()

	frontend := Endpoint{Namespace: "default", Labels: map[string]string{"app": "frontend"}}

	cnp := buildCNPInline("fqdn-nol7", map[string]string{"app": "frontend"}, nil, []policy.CNPEgressRule{
		{
			ToFQDNs: []policy.FQDNSelector{{MatchName: "example.com"}},
			ToPorts: []policy.CNPToPorts{{Ports: []policy.PortRule{{Port: "53", Protocol: "UDP"}}}},
		},
	})

	result := EvaluateCiliumNetworkPolicy(
		frontend,
		Endpoint{Namespace: "default"},
		Traffic{Port: 53, Protocol: "UDP"},
		[]LoadedPolicy{{File: "fqdn-nol7.yaml", Kind: "CiliumNetworkPolicy", Cilium: cnp}},
		nil,
	)
	if result.Egress != VerdictAllow {
		t.Fatalf("expected allow when no L7Name (FQDN doesn't gate); got %s", result.Egress)
	}
}

func TestEvaluateCiliumNetworkPolicy_MultiplePoliciesMerge(t *testing.T) {
	t.Parallel()

	frontend := Endpoint{Namespace: "default", Labels: map[string]string{"app": "frontend"}}
	backend := Endpoint{Namespace: "default", Labels: map[string]string{"app": "backend"}}

	policies := []LoadedPolicy{
		buildIN("policy-a", "default", map[string]string{"app": "frontend"}, nil, []policy.CNPEgressRule{
			{
				ToEndpoints: []policy.CNPEntitySelector{{MatchLabels: map[string]string{"app": "backend"}}},
				ToPorts:     []policy.CNPToPorts{{Ports: []policy.PortRule{{Port: "8080", Protocol: "TCP"}}}},
			},
		}),
	}

	result := EvaluateCiliumNetworkPolicy(frontend, backend, Traffic{Port: 8080, Protocol: "TCP"}, policies, nil)
	if result.Egress != VerdictAllow {
		t.Fatalf("expected egress allow; got %s", result.Egress)
	}
	if result.Ingress != VerdictUndetermined {
		t.Fatalf("expected ingress undetermined; got %s", result.Ingress)
	}
	if len(result.MatchingFiles) != 1 || result.MatchingFiles[0] != "policy-a.yaml" {
		t.Fatalf("unexpected MatchingFiles: %v", result.MatchingFiles)
	}
}

func TestEvaluateCiliumNetworkPolicy_Undetermined(t *testing.T) {
	t.Parallel()

	frontend := Endpoint{Namespace: "default", Labels: map[string]string{"app": "frontend"}}
	backend := Endpoint{Namespace: "default", Labels: map[string]string{"app": "backend"}}

	policies := []LoadedPolicy{
		buildIN("dst-scope", "default", map[string]string{"app": "backend"}, nil, nil),
	}

	result := EvaluateCiliumNetworkPolicy(frontend, backend, Traffic{Port: 80, Protocol: "TCP"}, policies, nil)
	if result.Egress != VerdictUndetermined || result.Ingress != VerdictUndetermined {
		t.Fatalf("expected undetermined/undetermined; got %s/%s", result.Ingress, result.Egress)
	}
	if result.MatchingFiles != nil {
		t.Fatalf("expected nil MatchingFiles for undetermined; got %v", result.MatchingFiles)
	}
}

func TestEvaluateCiliumNetworkPolicy_DNSWithWrongProtocol(t *testing.T) {
	t.Parallel()

	frontend := Endpoint{Namespace: "default", Labels: map[string]string{"app": "frontend"}}

	cnp := buildCNPInline("dns-udp-only", map[string]string{"app": "frontend"}, nil, []policy.CNPEgressRule{
		{
			ToPorts: []policy.CNPToPorts{{Ports: []policy.PortRule{{Port: "53", Protocol: "UDP"}}}},
		},
	})

	result := EvaluateCiliumNetworkPolicy(
		frontend,
		Endpoint{Namespace: "default"},
		Traffic{Port: 53, Protocol: "TCP"},
		[]LoadedPolicy{{File: "dns-udp.yaml", Kind: "CiliumNetworkPolicy", Cilium: cnp}},
		nil,
	)
	if result.Egress != VerdictDeny {
		t.Fatalf("expected deny (UDP protocol needed); got %s", result.Egress)
	}
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

func check[T comparable](t *testing.T, label string, want, got T) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %v; want %v", label, got, want)
	}
}

func checkSlice(t *testing.T, label string, want, got []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: len got=%d; want=%d", label, len(got), len(want))
		return
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("%s[%d]: got %q; want %q", label, i, got[i], want[i])
		}
	}
}

func buildCNPInline(name string, sel map[string]string,
	ingress []policy.CNPIngressRule,
	egress []policy.CNPEgressRule,
) *policy.CiliumNetworkPolicy {
	return &policy.CiliumNetworkPolicy{
		APIVersion: "cilium.io/v2",
		Kind:       "CiliumNetworkPolicy",
		Metadata: policy.CNPMetadata{
			Name:      name,
			Namespace: "default",
		},
		Spec: policy.CNPSpec{
			EndpointSelector: policy.CNPEntitySelector{
				MatchLabels: sel,
			},
			Ingress: ingress,
			Egress:  egress,
		},
	}
}

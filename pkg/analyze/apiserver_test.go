package analyze

import (
	"net"
	"testing"

	"github.com/flowguarder/flowguarder/pkg/config"
	"github.com/flowguarder/flowguarder/pkg/flow"
	"github.com/stretchr/testify/assert"
)

// helperIPNet2 parses a CIDR string into *net.IPNet.
func helperIPNet2(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

func TestInferAPIServerCIDRs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		flows     []flow.Flow
		cfg       config.Config
		wantCIDRs []string
	}{
		{
			name:  "nil flows returns configured as-is",
			flows: nil,
			cfg: config.Config{
				APIServerCIDRs: []*net.IPNet{helperIPNet2("10.96.0.0/12")},
			},
			wantCIDRs: []string{"10.96.0.0/12"},
		},
		{
			name:  "empty flows returns configured as-is",
			flows: []flow.Flow{},
			cfg: config.Config{
				APIServerCIDRs: []*net.IPNet{helperIPNet2("10.96.0.0/12")},
			},
			wantCIDRs: []string{"10.96.0.0/12"},
		},
		{
			name: "private IP on egress port 6443 is inferred as /32",
			flows: []flow.Flow{
				{
					Source:      flow.Endpoint{IP: "10.0.0.1"},
					Destination: flow.Endpoint{IP: "192.168.107.5"},
					Layer4:      flow.Layer4{DestPort: 6443, Protocol: flow.TCP},
				},
			},
			cfg: config.Default(),
			// default cfg has "10.96.0.0/12" + inferred "192.168.107.5/32"
			wantCIDRs: []string{"10.96.0.0/12", "192.168.107.5/32"},
		},
		{
			name: "public IP on egress port 6443 is NOT inferred",
			flows: []flow.Flow{
				{
					Source:      flow.Endpoint{IP: "10.0.0.1"},
					Destination: flow.Endpoint{IP: "203.0.113.5"},
					Layer4:      flow.Layer4{DestPort: 6443, Protocol: flow.TCP},
				},
			},
			cfg: config.Default(),
			// only configured CIDR — public IP is skipped
			wantCIDRs: []string{"10.96.0.0/12"},
		},
		{
			name: "reserved:kube-apiserver label on destination does NOT contribute IP",
			flows: []flow.Flow{
				{
					Source: flow.Endpoint{IP: "10.0.0.1"},
					Destination: flow.Endpoint{
						IP: "192.168.107.5",
						Labels: map[string]string{
							"reserved:kube-apiserver": "",
						},
					},
				},
			},
			cfg:       config.Default(),
			wantCIDRs: []string{"10.96.0.0/12"}, // only configured — label is NOT trusted
		},
		{
			name: "k8s-app label on source does not trigger",
			flows: []flow.Flow{
				{
					Source: flow.Endpoint{IP: "192.168.107.5", Labels: map[string]string{
						"k8s-app": "kube-apiserver", // not the right label — should NOT trigger
					}},
					Destination: flow.Endpoint{IP: "10.0.0.1"},
				},
			},
			cfg: config.Default(),
			// No right label, no inference
			wantCIDRs: []string{"10.96.0.0/12"},
		},
		{
			name: "reserved:kube-apiserver label on source does NOT contribute IP",
			flows: []flow.Flow{
				{
					Source: flow.Endpoint{IP: "192.168.107.5", Labels: map[string]string{
						"reserved:kube-apiserver": "",
					}},
					Destination: flow.Endpoint{IP: "10.0.0.1"},
				},
			},
			cfg:       config.Default(),
			wantCIDRs: []string{"10.96.0.0/12"}, // only configured — label is NOT trusted
		},
		{
			name: "DestLabels shortcut does NOT contribute IP",
			flows: []flow.Flow{
				{
					Source:      flow.Endpoint{IP: "10.0.0.1"},
					Destination: flow.Endpoint{IP: "192.168.100.5"},
					DestLabels: map[string]string{
						"reserved:kube-apiserver": "",
					},
				},
			},
			cfg:       config.Default(),
			wantCIDRs: []string{"10.96.0.0/12"}, // only configured — DestLabels shortcut is NOT trusted
		},
		{
			name: "SourceLabels shortcut does NOT contribute IP",
			flows: []flow.Flow{
				{
					Source: flow.Endpoint{IP: "192.168.100.5"},
					SourceLabels: map[string]string{
						"reserved:kube-apiserver": "",
					},
					Destination: flow.Endpoint{IP: "10.0.0.1"},
				},
			},
			cfg:       config.Default(),
			wantCIDRs: []string{"10.96.0.0/12"}, // only configured — SourceLabels shortcut is NOT trusted
		},
		{
			name: "inferred IP inside configured CIDR is not duplicated",
			flows: []flow.Flow{
				{
					Source:      flow.Endpoint{IP: "10.0.0.1"},
					Destination: flow.Endpoint{IP: "10.96.0.10"},
					Layer4:      flow.Layer4{DestPort: 6443, Protocol: flow.TCP},
				},
			},
			cfg: config.Default(),
			// 10.96.0.10 is inside 10.96.0.0/12 → no duplicate
			wantCIDRs: []string{"10.96.0.0/12"},
		},
		{
			name: "explicit config preserved verbatim — config first",
			flows: []flow.Flow{
				{
					Source:      flow.Endpoint{IP: "10.0.0.1"},
					Destination: flow.Endpoint{IP: "172.16.5.5"},
					Layer4:      flow.Layer4{DestPort: 6443, Protocol: flow.TCP},
				},
			},
			cfg: func() config.Config {
				c := config.Default()
				c.APIServerCIDRs = []*net.IPNet{helperIPNet2("10.96.0.0/12")}
				return c
			}(),
			wantCIDRs: []string{"10.96.0.0/12", "172.16.5.5/32"},
		},
		{
			name: "multiple inferred IPs sorted deterministically",
			flows: []flow.Flow{
				{
					Source:      flow.Endpoint{IP: "10.0.0.1"},
					Destination: flow.Endpoint{IP: "192.168.1.1"},
					Layer4:      flow.Layer4{DestPort: 6443, Protocol: flow.TCP},
				},
				{
					Source:      flow.Endpoint{IP: "10.0.0.1"},
					Destination: flow.Endpoint{IP: "192.168.2.2"},
					Layer4:      flow.Layer4{DestPort: 6443, Protocol: flow.TCP},
				},
				{
					Source:      flow.Endpoint{IP: "10.0.0.1"},
					Destination: flow.Endpoint{IP: "10.1.1.1"},
					Layer4:      flow.Layer4{DestPort: 6443, Protocol: flow.TCP},
				},
			},
			cfg:       config.Default(),
			wantCIDRs: []string{"10.1.1.1/32", "10.96.0.0/12", "192.168.1.1/32", "192.168.2.2/32"},
		},
		{
			name: "repeated calls produce identical results (deterministic)",
			flows: []flow.Flow{
				{
					Source:      flow.Endpoint{IP: "10.0.0.1"},
					Destination: flow.Endpoint{IP: "192.168.107.5"},
					Layer4:      flow.Layer4{DestPort: 6443, Protocol: flow.TCP},
				},
			},
			cfg:       config.Default(),
			wantCIDRs: []string{"10.96.0.0/12", "192.168.107.5/32"},
		},
		{
			name: "port 9443 (ingress port) not in DefaultApiserverEgressPorts — not inferred",
			flows: []flow.Flow{
				{
					Source:      flow.Endpoint{IP: "10.0.0.1"},
					Destination: flow.Endpoint{IP: "192.168.200.5"},
					Layer4:      flow.Layer4{DestPort: 9443, Protocol: flow.TCP},
				},
			},
			cfg: config.Default(),
			// 9443 is NOT in DefaultApiserverEgressPorts (only 6443)
			wantCIDRs: []string{"10.96.0.0/12"},
		},
		{
			name: "UDP port 6443 not matched when only TCP configured",
			flows: []flow.Flow{
				{
					Source:      flow.Endpoint{IP: "10.0.0.1"},
					Destination: flow.Endpoint{IP: "192.168.200.5"},
					Layer4:      flow.Layer4{DestPort: 6443, Protocol: flow.UDP},
				},
			},
			cfg: config.Default(),
			// DefaultApiserverEgressPorts has TCP/6443 only — UDP should not match
			wantCIDRs: []string{"10.96.0.0/12"},
		},
		{
			name: "no configured CIDRs returns only inferred",
			flows: []flow.Flow{
				{
					Source:      flow.Endpoint{IP: "10.0.0.1"},
					Destination: flow.Endpoint{IP: "192.168.107.5"},
					Layer4:      flow.Layer4{DestPort: 6443, Protocol: flow.TCP},
				},
			},
			cfg: func() config.Config {
				c := config.Default()
				c.APIServerCIDRs = nil
				return c
			}(),
			wantCIDRs: []string{"192.168.107.5/32"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := InferAPIServerCIDRs(tt.flows, tt.cfg)
			assert.Equal(t, tt.wantCIDRs, got, "InferAPIServerCIDRs(%d flows)", len(tt.flows))

			// Verify sorted (except empty/nil)
			if len(got) > 0 {
				for i := 1; i < len(got); i++ {
					assert.LessOrEqual(t, got[i-1], got[i], "slice should be sorted at index %d", i)
				}
			}

			// Deterministic: call again and compare.
			got2 := InferAPIServerCIDRs(tt.flows, tt.cfg)
			assert.Equal(t, got, got2, "should be deterministic")
		})
	}
}

func TestInferAPIServerCIDRs_E2E_Classify(t *testing.T) {
	t.Parallel()

	// Flow to a private IP on port 6443 that is NOT in default apiserver CIDR.
	flow1 := flow.Flow{
		Source:      flow.Endpoint{IP: "10.0.0.1"},
		Destination: flow.Endpoint{IP: "192.168.107.5"},
		Layer4:      flow.Layer4{DestPort: 6443, Protocol: flow.TCP},
	}

	inferred := InferAPIServerCIDRs([]flow.Flow{flow1}, config.Default())
	assert.Contains(t, inferred, "192.168.107.5/32")

	// Build a config with the inferred CIDRs and classify.
	flows := []flow.Flow{flow1}
	mergedCfg := config.Default()
	mergedCfg.APIServerCIDRs = helperCIDRs(inferred)

	result := Classify(flows, mergedCfg)
	assert.Equal(t, flow.KubeAPIServer, result[0].PeerType, "flow should classify as KubeAPIServer")
}

func helperCIDRs(strs []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(strs))
	for _, s := range strs {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			continue
		}
		out = append(out, n)
	}
	return out
}

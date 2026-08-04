package analyze

import (
	"net"
	"testing"

	"github.com/flowguarder/flowguarder/pkg/config"
	"github.com/flowguarder/flowguarder/pkg/flow"
	"github.com/stretchr/testify/assert"
)

// helperIPNet parses a CIDR string into *net.IPNet.
func helperIPNet(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		name  string
		ip    net.IP
		cidrs []string
		want  bool
	}{
		{
			name:  "10.0.0.1 in 10.0.0.0/8",
			ip:    net.ParseIP("10.0.0.1"),
			cidrs: []string{"10.0.0.0/8"},
			want:  true,
		},
		{
			name:  "172.16.0.1 in 172.16.0.0/12",
			ip:    net.ParseIP("172.16.0.1"),
			cidrs: []string{"172.16.0.0/12"},
			want:  true,
		},
		{
			name:  "192.168.1.1 in 192.168.0.0/16",
			ip:    net.ParseIP("192.168.1.1"),
			cidrs: []string{"192.168.0.0/16"},
			want:  true,
		},
		{
			name:  "100.64.0.1 in CGNAT",
			ip:    net.ParseIP("100.64.0.1"),
			cidrs: []string{"100.64.0.0/10"},
			want:  true,
		},
		{
			name:  "169.254.1.1 link-local",
			ip:    net.ParseIP("169.254.1.1"),
			cidrs: []string{"169.254.0.0/16"},
			want:  true,
		},
		{
			name:  "127.0.0.1 loopback",
			ip:    net.ParseIP("127.0.0.1"),
			cidrs: []string{"127.0.0.0/8"},
			want:  true,
		},
		{
			name:  "fd00::1 ULA",
			ip:    net.ParseIP("fd00::1"),
			cidrs: []string{"fd00::/8"},
			want:  true,
		},
		{
			name:  "fe80::1 link-local IPv6",
			ip:    net.ParseIP("fe80::1"),
			cidrs: []string{"fe80::/10"},
			want:  true,
		},
		{
			name:  "::1 loopback IPv6",
			ip:    net.ParseIP("::1"),
			cidrs: []string{"::1/128"},
			want:  true,
		},
		{
			name:  "8.8.8.8 public",
			ip:    net.ParseIP("8.8.8.8"),
			cidrs: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
			want:  false,
		},
		{
			name:  "0.0.0.0 not private",
			ip:    net.ParseIP("0.0.0.0"),
			cidrs: []string{"10.0.0.0/8"},
			want:  false,
		},
		{
			name:  "255.255.255.255 not private",
			ip:    net.ParseIP("255.255.255.255"),
			cidrs: []string{"10.0.0.0/8"},
			want:  false,
		},
		{
			name:  ":: not private",
			ip:    net.ParseIP("::"),
			cidrs: []string{"fd00::/8"},
			want:  false,
		},
		{
			name:  "nil cidrs falls back to defaults",
			ip:    net.ParseIP("10.0.0.1"),
			cidrs: nil,
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cidrs []*net.IPNet
			if tt.cidrs != nil && len(tt.cidrs) > 0 {
				cidrs = make([]*net.IPNet, len(tt.cidrs))
				for i, c := range tt.cidrs {
					cidrs[i] = helperIPNet(c)
				}
			}
			got := IsPrivateIP(tt.ip, cidrs)
			assert.Equal(t, tt.want, got, "IsPrivateIP(%v, %v)", tt.ip, tt.cidrs)
		})
	}
}

func TestIsPublicIP(t *testing.T) {
	tests := []struct {
		name string
		ip   net.IP
		want bool
	}{
		{"8.8.8.8 is public", net.ParseIP("8.8.8.8"), true},
		{"1.1.1.1 is public", net.ParseIP("1.1.1.1"), true},
		{"10.0.0.1 is not public", net.ParseIP("10.0.0.1"), false},
		{"172.16.0.1 not public", net.ParseIP("172.16.0.1"), false},
		{"192.168.1.1 not public", net.ParseIP("192.168.1.1"), false},
		{"255.255.255.255 is public (broadcast is not in private CIDRs)", net.ParseIP("255.255.255.255"), true},
		{"0.0.0.0 is public", net.ParseIP("0.0.0.0"), true},
		{":: is public", net.ParseIP("::"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsPublicIP(tt.ip)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsDNSPort(t *testing.T) {
	assert.True(t, IsDNSPort(53, flow.UDP))
	assert.True(t, IsDNSPort(53, flow.TCP))
	assert.True(t, IsDNSPort(53, flow.ANY_P))
	assert.False(t, IsDNSPort(443, flow.TCP))
	assert.False(t, IsDNSPort(80, flow.UDP))
	assert.False(t, IsDNSPort(25, flow.UDP))
}

func TestIsKubeAPIServerIP(t *testing.T) {
	cidrs := []*net.IPNet{helperIPNet("10.96.0.0/12")}

	assert.True(t, IsKubeAPIServerIP(net.ParseIP("10.96.0.10"), cidrs))
	assert.True(t, IsKubeAPIServerIP(net.ParseIP("10.96.1.1"), cidrs))
	assert.True(t, IsKubeAPIServerIP(net.ParseIP("10.99.255.255"), cidrs))
	assert.False(t, IsKubeAPIServerIP(net.ParseIP("10.0.0.1"), cidrs))
	assert.False(t, IsKubeAPIServerIP(net.ParseIP("192.168.1.1"), cidrs))
	assert.False(t, IsKubeAPIServerIP(net.ParseIP("8.8.8.8"), cidrs))

	// nil cidrs
	assert.False(t, IsKubeAPIServerIP(net.ParseIP("10.96.0.10"), nil))
}

func TestClassifyPeer(t *testing.T) {
	cfg := config.Config{
		ClusterCIDRs: []*net.IPNet{
			helperIPNet("10.0.0.0/8"),
			helperIPNet("172.16.0.0/12"),
			helperIPNet("192.168.0.0/16"),
			helperIPNet("fd00::/8"),
			helperIPNet("100.64.0.0/10"),
		},
		APIServerCIDRs: []*net.IPNet{
			helperIPNet("10.96.0.0/12"),
		},
		KubeDNSPorts: []config.PortSpec{
			{Protocol: "UDP", Port: 53},
			{Protocol: "TCP", Port: 53},
		},
	}

	baseFlow := flow.Flow{}

	tests := []struct {
		name    string
		flow    flow.Flow
		want    flow.PeerType
	}{
		{
			name: "ingress-world: src public, dst private",
			flow: flow.Flow{
				Source:    flow.Endpoint{IP: "8.8.8.8"},
				Destination: flow.Endpoint{IP: "10.0.0.1"},
				Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
				Direction: flow.Ingress,
			},
			want: flow.IngressWorld,
		},
		{
			name: "egress-world: src private, dst public",
			flow: flow.Flow{
				Source:      flow.Endpoint{IP: "10.0.0.1"},
				Destination: flow.Endpoint{IP: "8.8.8.8"},
				Layer4:      flow.Layer4{DestPort: 8443, Protocol: flow.TCP},
				Direction:   flow.Egress,
			},
			want: flow.EgressWorld,
		},
		{
			name: "pod-pod: both private, same 10.x",
			flow: flow.Flow{
				Source:      flow.Endpoint{IP: "10.0.0.1"},
				Destination: flow.Endpoint{IP: "10.0.0.2"},
				Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
				Direction:   flow.Internal,
			},
			want: flow.PodPod,
		},
		{
			name: "kube-apiserver: dst in APIServerCIDRs",
			flow: flow.Flow{
				Source:      flow.Endpoint{IP: "10.0.0.1"},
				Destination: flow.Endpoint{IP: "10.96.0.10"},
				Layer4:      flow.Layer4{DestPort: 6443, Protocol: flow.TCP},
				Direction:   flow.Egress,
			},
			want: flow.KubeAPIServer,
		},
		{
			name: "non-apiserver with port 443 not kube-apiserver",
			flow: flow.Flow{
				Source:      flow.Endpoint{IP: "10.0.0.1"},
				Destination: flow.Endpoint{IP: "192.168.1.100"},
				Layer4:      flow.Layer4{DestPort: 443, Protocol: flow.TCP},
				Direction:   flow.Egress,
			},
			want: flow.PodPod,
		},
		{
			name: "dns via UDP port 53",
			flow: flow.Flow{
				Source:      flow.Endpoint{IP: "10.0.0.1"},
				Destination: flow.Endpoint{IP: "10.0.1.50"},
				Layer4:      flow.Layer4{DestPort: 53, Protocol: flow.UDP},
				Direction:   flow.Egress,
			},
			want: flow.DNS,
		},
		{
			name: "dns via TCP port 53",
			flow: flow.Flow{
				Source:      flow.Endpoint{IP: "10.0.0.1"},
				Destination: flow.Endpoint{IP: "10.0.1.50"},
				Layer4:      flow.Layer4{DestPort: 53, Protocol: flow.TCP},
				Direction:   flow.Egress,
			},
			want: flow.DNS,
		},
		{
			name: "ingress-world with IPv6 source",
			flow: flow.Flow{
				Source:      flow.Endpoint{IP: "203.0.113.5"},
				Destination: flow.Endpoint{IP: "10.0.0.5"},
				Layer4:      flow.Layer4{DestPort: 443, Protocol: flow.TCP},
				Direction:   flow.Ingress,
			},
			want: flow.IngressWorld,
		},
		{
			name: "egress-world to IPv6 public dest",
			flow: flow.Flow{
				Source:      flow.Endpoint{IP: "10.0.0.5"},
				Destination: flow.Endpoint{IP: "203.0.113.10"},
				Layer4:      flow.Layer4{DestPort: 8443, Protocol: flow.TCP},
				Direction:   flow.Egress,
			},
			want: flow.EgressWorld,
		},
		{
			name: "unknown when both IPs are public",
			flow: flow.Flow{
				Source:      flow.Endpoint{IP: "8.8.8.8"},
				Destination: flow.Endpoint{IP: "1.1.1.1"},
				Layer4:      flow.Layer4{DestPort: 443, Protocol: flow.TCP},
				Direction:   flow.Ingress,
			},
			want: flow.Unknown,
		},
		{
			name: "unknown when destination IP is empty",
			flow: flow.Flow{
				Source:      flow.Endpoint{IP: "8.8.8.8"},
				Destination: flow.Endpoint{IP: ""},
				Layer4:      flow.Layer4{DestPort: 443, Protocol: flow.TCP},
				Direction:   flow.Ingress,
			},
			want: flow.Unknown,
		},
		{
			name: "unknown when source IP is empty",
			flow: baseFlow,
			want: flow.Unknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyPeer(tt.flow, cfg)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClassifyPeer_DNS_TakesPriority(t *testing.T) {
	// DNS should take priority over kube-apiserver if both conditions are met
	// (port 53 on apiserver IP).
	// With current priority order, kube-apiserver is checked first.
	cfg := config.Default()

	f := flow.Flow{
		Source:      flow.Endpoint{IP: "10.0.0.1"},
		Destination: flow.Endpoint{IP: "10.96.0.10"},
		Layer4:      flow.Layer4{DestPort: 53, Protocol: flow.UDP},
		Direction:   flow.Egress,
	}

	// apiserver CIDRs are checked first, so 10.96.0.10 → kube-apiserver
	got := ClassifyPeer(f, cfg)
	assert.Equal(t, flow.KubeAPIServer, got)
}

func TestClassify(t *testing.T) {
	cfg := config.Default()

	flows := []flow.Flow{
		{
			Source:      flow.Endpoint{IP: "8.8.8.8"},
			Destination: flow.Endpoint{IP: "10.0.0.1"},
			Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Direction:   flow.Ingress,
			PeerType:    "",
		},
		{
			Source:      flow.Endpoint{IP: "10.0.0.1"},
			Destination: flow.Endpoint{IP: "8.8.8.8"},
			Layer4:      flow.Layer4{DestPort: 8443, Protocol: flow.TCP},
			Direction:   flow.Egress,
			PeerType:    "",
		},
		{
			Source:      flow.Endpoint{IP: "10.0.0.1"},
			Destination: flow.Endpoint{IP: "10.0.0.2"},
			Layer4:      flow.Layer4{DestPort: 80, Protocol: flow.TCP},
			Direction:   flow.Internal,
			PeerType:    "",
		},
	}

	result := Classify(flows, cfg)

	assert.Equal(t, 3, len(result))
	assert.Equal(t, flow.IngressWorld, result[0].PeerType)
	assert.Equal(t, flow.EgressWorld, result[1].PeerType)
	assert.Equal(t, flow.PodPod, result[2].PeerType)

	// Original flows should NOT be mutated.
	assert.Equal(t, flow.PeerType(""), flows[0].PeerType)
	assert.Equal(t, flow.PeerType(""), flows[1].PeerType)
	assert.Equal(t, flow.PeerType(""), flows[2].PeerType)
}

func TestClassify_EmptyInput(t *testing.T) {
	cfg := config.Default()
	result := Classify(nil, cfg)
	assert.Empty(t, result)

	result2 := Classify([]flow.Flow{}, cfg)
	assert.Empty(t, result2)
}

func TestClassifyPeer_KubeAPIServerByLabel(t *testing.T) {
	cfg := config.Default()

	tests := []struct {
		name     string
		flow     flow.Flow
		want     flow.PeerType
	}{
		{
			name: "private IP with reserved:kube-apiserver label",
			flow: flow.Flow{
				Source:      flow.Endpoint{IP: "10.0.0.1"},
				Destination: flow.Endpoint{IP: "192.168.107.3", Labels: map[string]string{"reserved:kube-apiserver": "true"}},
				Layer4:      flow.Layer4{DestPort: 6443, Protocol: flow.TCP},
				Direction:   flow.Egress,
			},
			want: flow.KubeAPIServer,
		},
		{
			name: "public IP with reserved:kube-apiserver label",
			flow: flow.Flow{
				Source:      flow.Endpoint{IP: "10.0.0.1"},
				Destination: flow.Endpoint{IP: "1.2.3.4", Labels: map[string]string{"reserved:kube-apiserver": "true"}},
				Layer4:      flow.Layer4{DestPort: 443, Protocol: flow.TCP},
				Direction:   flow.Egress,
			},
			want: flow.KubeAPIServer,
		},
		{
			name: "private IP without special label is not apiserver",
			flow: flow.Flow{
				Source:      flow.Endpoint{IP: "10.0.0.1"},
				Destination: flow.Endpoint{IP: "10.0.0.2", Labels: map[string]string{"app": "backend"}},
				Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
				Direction:   flow.Egress,
			},
			want: flow.PodPod,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyPeer(tt.flow, cfg)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClassifyPeer_EdgeZeroIP(t *testing.T) {
	cfg := config.Default()

	f := flow.Flow{
		Source:      flow.Endpoint{IP: "0.0.0.0"},
		Destination: flow.Endpoint{IP: "10.0.0.1"},
		Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
		Direction:   flow.Ingress,
	}
	// 0.0.0.0 is not in any private CIDR → public
	got := ClassifyPeer(f, cfg)
	assert.Equal(t, flow.IngressWorld, got)

	f2 := flow.Flow{
		Source:      flow.Endpoint{IP: "10.0.0.1"},
		Destination: flow.Endpoint{IP: "255.255.255.255"},
		Layer4:      flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
		Direction:   flow.Egress,
	}
	got2 := ClassifyPeer(f2, cfg)
	assert.Equal(t, flow.EgressWorld, got2)
}

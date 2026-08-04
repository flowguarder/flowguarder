// Package analyze provides network-flow classification, aggregation, and
// statistics helpers for the flowguarder CLI.
package analyze

import (
	"net"

	"github.com/flowguarder/flowguarder/pkg/config"
	"github.com/flowguarder/flowguarder/pkg/flow"
)

// defaultPrivateCIDRs are the standard RFC 1918 / CGNAT / ULA / loopback /
// link-local ranges that the classifier considers "private".
var defaultPrivateCIDRs = []*net.IPNet{}

func init() {
	for _, cidr := range [...]string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",
		"169.254.0.0/16",
		"127.0.0.0/8",
		"fd00::/8",
		"fe80::/10",
		"::1/128",
	} {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("analyze: bug — invalid default private CIDR " + cidr + ": " + err.Error())
		}
		defaultPrivateCIDRs = append(defaultPrivateCIDRs, n)
	}
}

// IsPrivateIP reports whether ip is contained in any of the provided privateCIDRs.
func IsPrivateIP(ip net.IP, privateCIDRs []*net.IPNet) bool {
	cidrs := privateCIDRs
	if cidrs == nil {
		cidrs = defaultPrivateCIDRs
	}
	for _, cidr := range cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// IsKubeAPIServerIP reports whether ip is contained in any of the provided
// APIServerCIDRs from the config.
func IsKubeAPIServerIP(ip net.IP, apiCIDRs []*net.IPNet) bool {
	for _, cidr := range apiCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// IsPublicIP reports true when the address is NOT in any of the standard
// private/internal ranges (RFC 1918 / RFC 4193 / CGNAT / loopback / link-local).
func IsPublicIP(ip net.IP) bool {
	return !IsPrivateIP(ip, nil)
}

// IsDNSPort reports whether the given port is a well-known DNS port.
func IsDNSPort(port int, proto flow.Protocol) bool {
	return port == 53
}

// isDNSInConfig checks whether a given port matches any of the config's
// KubeDNSPorts regardless of protocol specificity.
func isDNSInConfig(port int, proto flow.Protocol, kdp []config.PortSpec) bool {
	for _, p := range kdp {
		if p.Port == port {
			if p.Protocol == "" {
				return true
			}
			if string(proto) == p.Protocol {
				return true
			}
		}
	}
	return false
}

// ClassifyPeer determines the PeerType for a single flow using the provided
// configuration.
//
// Classification priority order:
//
//	1. kube-apiserver — Destination IP is in APIServerCIDRs or the port is 443/6443
//	2. dns — Destination port is a DNS port (default 53) and matches KubeDNSPorts
//	3. ingress-world — Source is public, Destination is private
//	4. egress-world — Destination is public, Source is private
//	5. pod-pod — both endpoints are private
//	6. unknown — default fallback
func ClassifyPeer(f flow.Flow, cfg config.Config) flow.PeerType {
	dstIP := net.ParseIP(f.Destination.IP)
	srcIP := net.ParseIP(f.Source.IP)

	if dstIP == nil || srcIP == nil {
		return flow.Unknown
	}

	// --- kube-apiserver (IP-based) ---
	if IsKubeAPIServerIP(dstIP, cfg.APIServerCIDRs) {
		return flow.KubeAPIServer
	}

	// --- kube-apiserver (label-based fallback) ---
	if f.Destination.Labels["reserved:kube-apiserver"] != "" {
		return flow.KubeAPIServer
	}

	// --- DNS ---
	if IsDNSPort(int(f.Layer4.DestPort), f.Layer4.Protocol) && isDNSInConfig(53, f.Layer4.Protocol, cfg.KubeDNSPorts) {
		return flow.DNS
	}

	// --- ingress-world / egress-world / pod-pod ---
	srcIsPrivate := IsPrivateIP(srcIP, cfg.ClusterCIDRs)
	dstIsPrivate := IsPrivateIP(dstIP, cfg.ClusterCIDRs)

	if IsPublicIP(srcIP) && dstIsPrivate {
		return flow.IngressWorld
	}
	if IsPublicIP(dstIP) && srcIsPrivate {
		return flow.EgressWorld
	}
	if srcIsPrivate && dstIsPrivate {
		return flow.PodPod
	}

	return flow.Unknown
}

// Classify processes a slice of flows and returns a new slice with PeerType set
// on each flow. The original flows are not mutated; each flow is copied.
func Classify(flows []flow.Flow, cfg config.Config) []flow.Flow {
	result := make([]flow.Flow, len(flows))
	for i := range flows {
		result[i] = flows[i]
		result[i].PeerType = ClassifyPeer(result[i], cfg)
	}
	return result
}

package analyze

import (
	"net"
	"sort"

	"github.com/flowguarder/flowguarder/pkg/config"
	"github.com/flowguarder/flowguarder/pkg/flow"
)

// InferAPIServerCIDRs scans the parsed flow slice for indicators that a
// workload is the Kubernetes API server and appends those addresses to the
// configured apiserver CIDR list.
//
// Inference signals (each flow scanned once):
//
//  1. Destination port ∈ cfg.ApiserverEgressPorts AND destination IP is
//     private → collect as /32.
//
// The returned list is the MERGED result: configured CIDRs first (explicit
// config takes precedence), then newly inferred /32 entries that are NOT
// already covered by an existing entry. Deterministic: deduplicated and
// sorted.
//
// The input slices and maps are never mutated.
func InferAPIServerCIDRs(flows []flow.Flow, cfg config.Config) []string {
	// Start with configured CIDR strings (explicit config first).
	configured := make([]string, 0, len(cfg.APIServerCIDRs))
	for _, cidr := range cfg.APIServerCIDRs {
		if cidr != nil {
			configured = append(configured, cidr.String())
		}
	}

	if len(flows) == 0 {
		sort.Strings(configured)
		return configured
	}

	// Build a lookup set for egress ports.
	type portKey struct {
		port     int
		protocol string
	}
	egressPortSet := make(map[portKey]bool, len(cfg.ApiserverEgressPorts))
	for _, ps := range cfg.ApiserverEgressPorts {
		egressPortSet[portKey{port: ps.Port, protocol: ps.Protocol}] = true
	}

	// Collect raw IP strings to avoid redundant net.ParseIP calls.
	inferredRaw := make(map[string]struct{})

	for i := range flows {
		f := &flows[i]

		var dstIP net.IP
		if f.Destination.IP != "" {
			dstIP = net.ParseIP(f.Destination.IP)
		}

		// Signal 1: destination port+protocol matches apiserver egress AND dest is private.
		pk := portKey{port: int(f.Layer4.DestPort), protocol: string(f.Layer4.Protocol)}
		if _, portMatches := egressPortSet[pk]; portMatches {
			if dstIP != nil && IsPrivateIP(dstIP, nil) {
				ipv4 := dstIP.To4()
				ipStr := f.Destination.IP
				if ipv4 != nil {
					ipStr = ipv4.String()
				}
				inferredRaw[ipStr] = struct{}{}
			}
		}
	}

	// Build set of configured IPNets for overlap check.
	coveredCheck := coverIPNets(cfg.APIServerCIDRs)

	// Merge: add only inferred IPs not already covered by configured CIDRs.
	for raw := range inferredRaw {
		ip := net.ParseIP(raw)
		if ip == nil {
			continue
		}
		// Check overlap using the raw 4/16-byte IP directly against configured CIDRs.
		// For 4-byte IPs, parsedBy4 ensures we pass a 4-byte slice (to4() returns
		// []byte, not net.IP, so we reconstruct).
		contains := false
		if coveredCheck != nil {
			if ip.To4() != nil {
				// Reconstruct as a 4-byte net.IP so CIDR.Contains works.
				by4 := ip.To4()
				if len(by4) == 4 {
					p4 := make(net.IP, 4)
					copy(p4, by4)
					contains = ipContainedInAny(p4, coveredCheck)
				}
			} else {
				padded := paddedIP(ip)
				contains = ipContainedInAny(padded, coveredCheck)
			}
		}
		if contains {
			continue // already inside a configured CIDR — redundant
		}
		// Add as /32 (IPv4) or /128 (IPv6).
		if ip.To4() != nil {
			configured = append(configured, raw+"/32")
		} else {
			configured = append(configured, raw+"/128")
		}
	}

	sort.Strings(configured)
	return configured
}

// paddedIP returns a 16-byte representation of ip (IPv6-mapped for v4).
func paddedIP(ip net.IP) net.IP {
	ipv4 := ip.To4()
	if ipv4 != nil {
		// Convert to IPv6-mapped form so it can be checked against /12 CIDRs.
		result := make([]byte, 16)
		copy(result[12:], ipv4)
		return result
	}
	if len(ip) == 4 {
		result := make([]byte, 16)
		copy(result[12:], ip)
		return result
	}
	// Already 16 bytes — copy to ensure right-size.
	result := make([]byte, 16)
	copy(result, ip)
	return result
}

// ipContainedInAny checks if the given 16-byte IP is contained in any of the CIDRs.
func ipContainedInAny(ip net.IP, cidrs []*net.IPNet) bool {
	for _, cidr := range cidrs {
		if cidr != nil && cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// coverIPNets extracts non-nil *net.IPNet entries from a config slice.
func coverIPNets(cidrs []*net.IPNet) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if c != nil {
			out = append(out, c)
		}
	}
	return out
}

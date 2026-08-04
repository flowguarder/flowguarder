package anomaly

import (
	"net"

	"github.com/flowguarder/flowguarder/pkg/analyze"
	"github.com/flowguarder/flowguarder/pkg/config"
	"github.com/flowguarder/flowguarder/pkg/flow"
)

// PublicEgressDetector flags egress flows to public (non-RFC1918) IPs
// from workloads not in a public egress allowlist.
type PublicEgressDetector struct{}

var _ Detector = (*PublicEgressDetector)(nil)

// Detect inspects flows classified as egress-world (PeerType==EgressWorld).
// If the destination IP is public and NOT covered by the allowlisted CIDRs
// or KnownGoodExternalEndpoints, an anomaly is emitted grouped per source
// workload.
func (d *PublicEgressDetector) Detect(
	flows []flow.Flow,
	patterns []Pattern,
	workloads analyze.Workloads,
	cfg config.Config,
) []Anomaly {
	type workEgress struct {
		workload string
		destIPs  map[string]struct{}
		domains  map[string]struct{}
	}

	allowedWorkloads := allowedWorkloadSet(cfg.PublicEgressAllowlistCIDRs, workloads)
	seen := make(map[string]*workEgress)

	for _, f := range flows {
		if f.PeerType != flow.EgressWorld {
			continue
		}

		dstIP := net.ParseIP(f.Destination.IP)
		if dstIP == nil {
			continue
		}

		// Check if the destination IP is in the allowlist CIDRs.
		if isCIDRInAllowlist(dstIP, cfg.PublicEgressAllowlistCIDRs) {
			continue
		}

		srcWID := resolveWorkloadID(f.Source, workloads)
		if srcWID == "" {
			srcWID = f.Source.IP
		}

		// Skip allowlisted workloads.
		if allowedWorkloads[srcWID] {
			continue
		}

		// Skip known-good endpoints (domain matching via L7 hint).
		if isKnownGoodDomain(f, cfg.KnownGoodExternalEndpoints) {
			continue
		}

		// DNS traffic to public IPs is common (e.g. external DNS resolvers),
		// skip to reduce noise.
		if f.Layer4.DestPort == 53 {
			continue
		}

		g, ok := seen[srcWID]
		if !ok {
			g = &workEgress{
				workload: srcWID,
				destIPs:  make(map[string]struct{}),
				domains:  make(map[string]struct{}),
			}
			seen[srcWID] = g
		}
		g.destIPs[f.Destination.IP] = struct{}{}
		if f.L7 != nil && f.L7.Host != "" {
			g.domains[f.L7.Host] = struct{}{}
		}
	}

	if len(seen) == 0 {
		return nil
	}

	anomalies := make([]Anomaly, 0, len(seen))
	for _, g := range seen {
		evidence := map[string]any{
			"source_workload": g.workload,
			"dest_count":      len(g.destIPs),
			"destinations":    keys(g.destIPs),
		}
		if len(g.domains) > 0 {
			evidence["domains"] = keys(g.domains)
		}

		anomalies = append(anomalies, NewAnomaly(
			"public-egress",
			SeverityMedium,
			g.workload,
			"Traffic to public (non-RFC1918) IPs detected",
			evidence,
		))
	}
	return anomalies
}

// isKnownGoodDomain checks if the flow's L7 host matches a known-good domain.
func isKnownGoodDomain(f flow.Flow, knownGood []string) bool {
	if f.L7 == nil || f.L7.Host == "" {
		return false
	}
	host := f.L7.Host
	for _, kg := range knownGood {
		if host == kg || host == kg+".com" || host == kg+".io" || host == kg+".net" {
			return true
		}
	}
	return false
}

func isCIDRInAllowlist(ip net.IP, cidrs []*net.IPNet) bool {
	for _, c := range cidrs {
		if c.Contains(ip) {
			return true
		}
	}
	return false
}

func allowedWorkloadSet(allowlist []*net.IPNet, workloads analyze.Workloads) map[string]bool {
	set := make(map[string]bool)
	// Workloads are identified by namespace/name; allowlist by CIDR.
	// For this implementation, the allowlist is CIDR-based, not workload-based.
	// This function returns an empty set since config uses CIDRs not workload names.
	_ = allowlist
	_ = workloads
	return set
}

func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

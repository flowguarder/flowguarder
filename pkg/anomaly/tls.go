package anomaly

import (
	"strings"

	"github.com/flowguarder/flowguarder/pkg/analyze"
	"github.com/flowguarder/flowguarder/pkg/config"
	"github.com/flowguarder/flowguarder/pkg/flow"
)

// TLSDetector flags flows with L7 SNI/HTTPHost hints pointing to domains
// not in the known-good allowlist.
type TLSDetector struct{}

var _ Detector = (*TLSDetector)(nil)

// Detect inspects flows with L7 hints (Type "tls" or "http") where the Host
// field contains a domain name. Domains not matching any entry in
// cfg.KnownGoodExternalEndpoints are flagged as anomalies.
func (d *TLSDetector) Detect(
	flows []flow.Flow,
	patterns []Pattern,
	workloads analyze.Workloads,
	cfg config.Config,
) []Anomaly {
	// Build a lookup of known-good domains.
	knownGood := make(map[string]struct{})
	for _, d := range cfg.KnownGoodExternalEndpoints {
		knownGood[strings.ToLower(d)] = struct{}{}
	}

	if len(knownGood) == 0 {
		return nil
	}

	// Group suspicious domains by source workload.
	type domainInfo struct {
		workload string
		domains  map[string]struct{}
		count    int
	}
	seen := make(map[string]*domainInfo)

	for _, f := range flows {
		if f.L7 == nil || f.L7.Host == "" {
			continue
		}
		if f.L7.Type != "tls" && f.L7.Type != "http" {
			continue
		}

		domain := strings.ToLower(f.L7.Host)
		// Skip domains that are known-good.
		if _, ok := knownGood[domain]; ok {
			continue
		}

		// Skip DNS query names (the query field is more appropriate for DNS).
		if f.PeerType == flow.DNS {
			continue
		}

		srcWID := resolveWorkloadID(f.Source, workloads)
		if srcWID == "" {
			srcWID = f.Source.IP
		}

		g, ok := seen[srcWID]
		if !ok {
			g = &domainInfo{
				workload: srcWID,
				domains:  make(map[string]struct{}),
			}
			seen[srcWID] = g
		}
		g.domains[domain] = struct{}{}
		g.count++
	}

	if len(seen) == 0 {
		return nil
	}

	anomalies := make([]Anomaly, 0, len(seen))
	for _, g := range seen {
		anomalies = append(anomalies, NewAnomaly(
			"tls-unknown-domain",
			SeverityMedium,
			g.workload,
			"TLS/SNI traffic to unknown domain detected",
			map[string]any{
				"source_workload": g.workload,
				"domain_count":    len(g.domains),
				"unknown_domains": keys(g.domains),
				"flow_count":      g.count,
			},
		))
	}
	return anomalies
}

// Package policy generates Kubernetes NetworkPolicy and CiliumNetworkPolicy
// manifests from observed network flow patterns.
package policy

import (
	"log"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/flowguarder/flowguarder/pkg/analyze"
	"github.com/flowguarder/flowguarder/pkg/anomaly"
	"github.com/flowguarder/flowguarder/pkg/config"
	"github.com/flowguarder/flowguarder/pkg/flow"
)

// BuildOptions controls policy generation behaviour.
type BuildOptions struct {
	// Cilium enables CiliumNetworkPolicy output alongside standard NetworkPolicy.
	Cilium bool
	// DefaultDeny adds a deny-all stub when the workload has observed traffic.
	DefaultDeny bool
	// Strict skips safety margins (no DNS, kube-apiserver egress auto-inclusion).
	Strict bool
	// ExcludeAnomalyTypes filters out anomalies whose Type is in this list.
	ExcludeAnomalyTypes []string
	// Config holds optional config.Config so the builder can read
	// ApiserverIngressPorts, PublicServices, and APIServerCIDRs. When nil,
	// the builder falls back to no apiserver sentinel and no public-services
	// shortcut (backward-compatible behaviour).
	Config *config.Config `yaml:"-" json:"-"`
}

// Policy holds the intermediate, source-agnostic policy model produced by Build().
type Policy struct {
	// WorkloadID uniquely identifies a workload as "namespace/name".
	WorkloadID string
	// WorkloadNamespace is the Kubernetes namespace.
	WorkloadNamespace string
	// WorkloadName is the resolved workload name.
	WorkloadName string
	// IngressRules lists allowed ingress flows for this workload.
	IngressRules []IngressRule
	// EgressRules lists allowed egress flows from this workload.
	EgressRules []EgressRule
}

// IngressRule represents a single ingress rule derived from observed traffic.
type IngressRule struct {
	// FromWorkloads lists workload selectors (label format or "namespace/name")
	// that are permitted to send traffic.
	FromWorkloads []string
	// FromEntities lists entity sentinels (e.g. "entity:host") for reserved
	// peers; consumed ONLY by the Cilium renderer; the NetPol renderer ignores
	// this field.
	FromEntities []string
	// Ports lists the permitted L4 ports.
	Ports []PortSpec
	// Description is a human-readable note for this rule.
	Description string
}

// EgressRule represents a single egress rule derived from observed traffic.
type EgressRule struct {
	// ToWorkloads lists workload selectors permitted to receive traffic.
	ToWorkloads []string
	// ToNamespaces lists namespaces whose pods are permitted to receive traffic (DNS fallback).
	ToNamespaces []string
	// ToCIDRs lists permitted CIDR ranges (for world egress).
	ToCIDRs []string
	// ToEntities lists entity sentinels (e.g. "entity:host") for reserved
	// peers; consumed ONLY by the Cilium renderer; the NetPol renderer ignores
	// this field.
	ToEntities []string
	// ToPorts lists the permitted L4 ports for workload egress.
	ToPorts []PortSpec
	// Description is a human-readable note for this rule.
	Description string
}

// PortSpec describes a single L4 port/protocol pair.
type PortSpec struct {
	Port        uint16
	Protocol    string
	Description string
}

// --- internal aggregators ---

// portKey is "proto/port" for dedup.
func portKey(port uint16, proto string) string {
	return proto + "/" + itoa(int(port))
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	var buf [20]byte
	n := len(buf)
	for i > 0 {
		n--
		buf[n] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		n--
		buf[n] = '-'
	}
	return string(buf[n:])
}

// wKey returns "namespace/name" for a flow endpoint.
func wKey(ns, name string) string {
	if ns != "" {
		return ns + "/" + name
	}
	return name
}

// resolveWlKey returns the workload key in "namespace/name" form, using the
// same resolution logic as analyze.Aggregate().
//
// This is necessary because f.Source.PodName / f.Destination.PodName may
// contain a pod-template-hash suffix (e.g. "frontend-7d3f9abc") which differs
// from the cleaned workload name (e.g. "frontend") stored in the workloads map.
// By re-resolving via analyze.ResolveWorkload we get keys that match the
// workload IDs in the caller's workloads map and isObserved map.
func resolveWlKey(ep flow.Endpoint) string {
	wl := analyze.ResolveWorkload(ep)
	return wl.Namespace + "/" + wl.Name
}

// observedWl tracks per-workload aggregation state.
type observedWl struct {
	ingress map[flowKey]*flowEntry
	egress  map[flowKey]*flowEntry
}

// flowKey groups flows by source/dest + port + proto.
type flowKey struct {
	peer     string
	port     uint16
	proto    string
	cidr     string // "world" for public egress, "" for pod-pod
	entities string // reserved entity sentinel from reservedEntities(), "" if none
}

// flowEntry accumulates counts and timestamps.
type flowEntry struct {
	count     int
	firstSeen time.Time
	lastSeen  time.Time
	hasL7DNS  bool
	hasL7HTTP bool
}

// Build generates a list of NetworkPolicy objects from the supplied flows,
// patterns, workloads and optional anomaly data.
//
// Output is deterministic: policies are sorted by WorkloadID.
// Skips workloads with zero observed traffic patterns and logs a warning.
func Build(flows []flow.Flow, patterns []anomaly.Pattern, workloads analyze.Workloads, anomalies []anomaly.Anomaly, opts BuildOptions) []Policy {
	// Build observed-workload set and aggregation maps.
	isObserved := make(map[string]bool, len(workloads))
	agg := make(map[string]*observedWl)

	for _, f := range flows {
		if !f.Verdict.IsAllowed() {
			continue
		}
		if f.IsReply {
			continue
		}

		srcKey := resolveWlKey(f.Source)
		dstKey := resolveWlKey(f.Destination)
		isObserved[srcKey] = true
		isObserved[dstKey] = true

		proto := string(f.Layer4.Protocol)
		port := f.Layer4.DestPort

		if agg[dstKey] == nil {
			agg[dstKey] = &observedWl{
				ingress: make(map[flowKey]*flowEntry),
				egress:  make(map[flowKey]*flowEntry),
			}
		}
		if agg[srcKey] == nil {
			agg[srcKey] = &observedWl{
				ingress: make(map[flowKey]*flowEntry),
				egress:  make(map[flowKey]*flowEntry),
			}
		}

		switch f.Direction {
		case flow.Ingress, flow.Internal:
			// Traffic entering dstKey from srcKey.
			var cidr string
			var entities string
			dstIP := net.ParseIP(f.Destination.IP)
			srcIP := net.ParseIP(f.Source.IP)
			isWorldIngress := dstIP != nil && srcIP != nil && analyze.IsPublicIP(srcIP) && analyze.IsPrivateIP(dstIP, nil)
			if isSyntheticEndpoint(f.Source) {
				cidr = classifySyntheticPeer(srcIP, opts.Config)
				entities = reservedEntities(f.Source)
				// Scope apiserver-port override: only the actual kube-apiserver peer triggers it.
				if isKubeAPIServerPeer(f.Source, opts.Config) && opts.Config != nil {
					for _, ps := range opts.Config.ApiserverIngressPorts {
						if f.Layer4.DestPort == uint16(ps.Port) && string(f.Layer4.Protocol) == ps.Protocol {
							cidr = "apiserver"
							break
						}
					}
				}
			} else if isWorldIngress {
				cidr = "world"
			} else if opts.Config != nil && isKubeAPIServerPeer(f.Source, opts.Config) {
				for _, ps := range opts.Config.ApiserverIngressPorts {
					if f.Layer4.DestPort == uint16(ps.Port) && string(f.Layer4.Protocol) == ps.Protocol {
						cidr = "apiserver"
						break
					}
				}
			}
			k := flowKey{peer: srcKey, port: port, proto: proto, cidr: cidr, entities: entities}
			e := agg[dstKey].ingress[k]
			if e == nil {
				e = &flowEntry{}
				agg[dstKey].ingress[k] = e
			}
			e.count++
			e.updateTime(f.Time)
			if f.L7 != nil {
				if f.L7.Type == "dns" {
					e.hasL7DNS = true
				}
				if f.L7.Type == "http" {
					e.hasL7HTTP = true
				}
			}

		case flow.Egress:
			// Traffic leaving srcKey toward dstKey.
			var cidr string
			var entities string
			dstIP := net.ParseIP(f.Destination.IP)
			srcIP := net.ParseIP(f.Source.IP)
			isWorldEgress := dstIP != nil && srcIP != nil && analyze.IsPublicIP(dstIP) && analyze.IsPrivateIP(srcIP, nil)
			if isSyntheticEndpoint(f.Destination) {
				cidr = classifySyntheticPeer(dstIP, opts.Config)
				entities = reservedEntities(f.Destination)
				// Scope apiserver-port override: only the actual kube-apiserver peer triggers it.
				if isKubeAPIServerPeer(f.Destination, opts.Config) && opts.Config != nil {
					for _, ps := range opts.Config.ApiserverEgressPorts {
						if f.Layer4.DestPort == uint16(ps.Port) && string(f.Layer4.Protocol) == ps.Protocol {
							cidr = "apiserver"
							break
						}
					}
				}
			} else if isWorldEgress {
				cidr = "world"
			} else if opts.Config != nil && isKubeAPIServerPeer(f.Destination, opts.Config) {
				for _, ps := range opts.Config.ApiserverEgressPorts {
					if f.Layer4.DestPort == uint16(ps.Port) && string(f.Layer4.Protocol) == ps.Protocol {
						cidr = "apiserver"
						break
					}
				}
			}
			k := flowKey{peer: dstKey, port: port, proto: proto, cidr: cidr, entities: entities}
			e := agg[srcKey].egress[k]
			if e == nil {
				e = &flowEntry{}
				agg[srcKey].egress[k] = e
			}
			e.count++
			e.updateTime(f.Time)
			if f.L7 != nil {
				if f.L7.Type == "dns" {
					e.hasL7DNS = true
				}
				if f.L7.Type == "http" || f.L7.Type == "tls" {
					e.hasL7HTTP = true
				}
			}

			// Symmetric ingress: mirror egress for non-synthetic, non-world destinations.
			if cidr == "" && !isSyntheticEndpoint(f.Destination) {
				var mirrorCIDR string
				var mirrorEntities string
				if isSyntheticEndpoint(f.Source) {
					mirrorCIDR = classifySyntheticPeer(srcIP, opts.Config)
					mirrorEntities = reservedEntities(f.Source)
				}
				ik := flowKey{peer: srcKey, port: port, proto: proto, cidr: mirrorCIDR, entities: mirrorEntities}
				ie := agg[dstKey].ingress[ik]
				if ie == nil {
					ie = &flowEntry{}
					agg[dstKey].ingress[ik] = ie
				}
				ie.count++
				ie.updateTime(f.Time)
				if f.L7 != nil {
					if f.L7.Type == "dns" {
						ie.hasL7DNS = true
					}
					if f.L7.Type == "http" {
						ie.hasL7HTTP = true
					}
				}
			}
		}
	}

	// Build policies in deterministic order.
	var policies []Policy
	for _, id := range workloads.SortedIDs() {
		wd, ok := workloads[analyze.WorkloadID(id)]
		if !ok {
			continue
		}
		if isSyntheticWorkload(id, wd) {
			log.Printf("flowguarder: policy: skipping synthetic workload %q", id)
			continue
		}
		if !isObserved[id] {
			log.Printf("flowguarder: policy: skipping workload %q: zero observed traffic", id)
			continue
		}

		pw := agg[id]
		if pw == nil {
			// Still observed (was seen as peer in another workload's flow),
			// but has no direct ingress/egress data — skip.
			log.Printf("flowguarder: policy: skipping workload %q: empty rules", id)
			continue
		}

		p := buildPolicyFromAgg(id, wd, pw, workloads, opts)
		if len(p.IngressRules) == 0 && len(p.EgressRules) == 0 {
			log.Printf("flowguarder: policy: skipping workload %q: empty rules", id)
			continue
		}
		policies = append(policies, p)
	}

	// sort by WorkloadID for deterministic output.
	sort.Slice(policies, func(i, j int) bool {
		return policies[i].WorkloadID < policies[j].WorkloadID
	})

	return policies
}

// reservedEntities extracts reserved:* label keys from an endpoint, strips the
// "reserved:" prefix, sorts the results, joins with ",", and returns
// "entity:<list>". Returns "" if the endpoint has no reserved:* labels.
//
// Labels are sorted so output is deterministic regardless of map iteration order.
func reservedEntities(ep flow.Endpoint) string {
	var ids []string
	for k := range ep.Labels {
		if strings.HasPrefix(k, "reserved:") {
			ids = append(ids, k[len("reserved:"):])
		}
	}
	if len(ids) == 0 {
		return ""
	}
	sort.Strings(ids)
	return "entity:" + strings.Join(ids, ",")
}

// isKubeAPIServerPeer returns true when the endpoint represents the kube-apiserver
// workload — either by carrying the reserved:kube-apiserver label key, or by
// matching Config.ApiserverWorkloadSelector when that is configured.
func isKubeAPIServerPeer(ep flow.Endpoint, cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	if _, ok := ep.Labels["reserved:kube-apiserver"]; ok {
		return true
	}
	wl := analyze.ResolveWorkload(ep)
	return isKubeAPIServerWorkload(wKey(ep.Namespace, wl.Name), wl, cfg.ApiserverWorkloadSelector)
}

// isSyntheticEndpoint returns true when the endpoint resolves to a synthetic
// workload (pvt, pub, or unknown "-"). Used as a fallback for world CIDR
// detection when the Goldmane parser sets all flow IPs to 0.0.0.0.
func isSyntheticEndpoint(ep flow.Endpoint) bool {
	wl := analyze.ResolveWorkload(ep)
	if wl.Name == "pvt" || wl.Name == "pub" || wl.Name == "-" {
		return true
	}
	for k := range ep.Labels {
		if strings.HasPrefix(k, "reserved:") {
			return true
		}
	}
	return false
}

// classifySyntheticPeer determines the CIDR string for a synthetic peer endpoint
// based on its IP and the configured APIServerCIDRs.
// Returns "apiserver" if the IP is within any APIServerCIDR,
// returns "ip/32" if the IP is private (internal node/peer CIDR),
// returns "world" for public or unparseable IPs.
func classifySyntheticPeer(ip net.IP, cfg *config.Config) string {
	if ip == nil || ip.String() == "" {
		return "world"
	}
	// Check APIServerCIDRs against the parsed 4-byte IP for reliable CIDR matching.
	if cfg != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			p4 := make(net.IP, 4)
			copy(p4, ipv4)
			if analyze.IsKubeAPIServerIP(p4, cfg.APIServerCIDRs) {
				return "apiserver"
			}
		}
	}
	// Private IP → emit specific /32 CIDR (internal node/peer).
	if analyze.IsPrivateIP(ip, nil) {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String() + "/32"
		}
		return ip.String() + "/32"
	}
	// Public or unparseable → world.
	return "world"
}

// isKubeAPIServerWorkload returns true when the given workload (identified by
// its "namespace/name" ID and resolved Workload struct) matches the supplied
// selector.
//
// When selector is nil the function returns false.
// When the workload's Namespace or Name is empty the function falls back to
// parsing id as "namespace/name" via strings.IndexByte.  If id also lacks "/"
// the function returns false.
func isKubeAPIServerWorkload(id string, wl analyze.Workload, selector *config.WorkloadSelector) bool {
	if selector == nil {
		return false
	}
	ns := wl.Namespace
	name := wl.Name
	if ns == "" || name == "" {
		if idx := strings.IndexByte(id, '/'); idx > 0 {
			ns = id[:idx]
			name = id[idx+1:]
		}
	}
	if ns == "" || name == "" {
		return false
	}
	return ns == selector.Namespace && name == selector.Name
}

func isSyntheticWorkload(id string, w analyze.Workload) bool {
	if w.Name == "pub" || w.Name == "pvt" {
		return true
	}
	if w.Name == "-" {
		return true
	}
	if w.Namespace == "" || w.Namespace == "-" {
		return true
	}
	if strings.HasPrefix(id, "-/") {
		return true
	}
	if strings.Contains(id, "/-") {
		return true
	}
	return false
}

func (e *flowEntry) updateTime(t time.Time) {
	if e.firstSeen.IsZero() || t.Before(e.firstSeen) {
		e.firstSeen = t
	}
	if e.lastSeen.IsZero() || t.After(e.lastSeen) {
		e.lastSeen = t
	}
}

func countDesc(count int) string {
	return "observed " + itoa(count) + " times"
}

// srcSelectorFor resolves a peer workload key to a selector string.
// When policyNs differs from the peer's namespace it prefixes the encoded
// form with "peerNamespace/peerName" so cross-namespace peers carry their
// namespace explicitly: "peerNs/peerName,label1=v1,..."
// When the peer is in the same namespace only the label selector is returned:
// "label1=v1,...".  If labels are empty it falls back to "peerNs/peerName".
func srcSelectorFor(policyNs string, id string, workloads analyze.Workloads) string {
	wd, hasWl := workloads[analyze.WorkloadID(id)]

	// Determine the peer's own namespace from the key.
	peerNs := policyNs
	if hasWl {
		peerNs = wd.Namespace
	} else {
		// Extract namespace from "namespace/name" key.
		if idx := strings.IndexByte(id, '/'); idx >= 0 {
			peerNs = id[:idx]
		}
	}

	if hasWl {
		sel := analyze.StripUnstableLabels(analyze.ResolveSelectors(wd))
		if len(sel) > 0 {
			var parts []string
			keys := make([]string, 0, len(sel))
			for k := range sel {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				parts = append(parts, k+"="+sel[k])
			}
			encodedLabels := strings.Join(parts, ",")
			// Cross-namespace: prefix with "peerNs/peerName"
			if policyNs != "" && peerNs != "" && policyNs != peerNs {
				return peerNs + "/" + wd.Name + "," + encodedLabels
			}
			return encodedLabels
		}
		// No labels but we still have the workload — return namespace/name.
		if peerNs != "" && policyNs != peerNs {
			return peerNs + "/" + wd.Name
		}
		return wd.Name
	}

	// No workload known — return key as-is (already "ns/name" for cross-ns).
	return id
}

// buildPolicyFromAgg constructs a Policy from the aggregation map.
func buildPolicyFromAgg(id string, wd analyze.Workload, pw *observedWl, workloads analyze.Workloads, opts BuildOptions) Policy {
	p := Policy{
		WorkloadID:        id,
		WorkloadNamespace: wd.Namespace,
		WorkloadName:      wd.Name,
	}

	p.IngressRules = buildIngressRules(pw.ingress, wd.Namespace, wd.Name, workloads, opts)

	p.EgressRules = buildEgressRules(pw.egress, wd.Namespace, workloads)

	// Synthesize egress rules from PublicServiceSpec.EgressPorts for long-lived
	// infrastructure connections (e.g. hubble-peer:80).  Even when only reply
	// flows were observed in the input, the workload needs an egress rule to
	// reach those infrastructure endpoints.  Dual-carry: ToEntities=["entity:world"]
	// AND ToCIDRs=["0.0.0.0/0"] so CNP renders toEntities: [world] and NP
	// renders 0.0.0.0/0.  Dedup WITHIN the synthesized rule only.
	if !opts.Strict && opts.Config != nil {
		for _, svc := range opts.Config.PublicServices {
			if svc.Namespace == wd.Namespace && svc.Name == wd.Name && len(svc.EgressPorts) > 0 {
				seenPorts := make(map[string]bool)
				var ports []PortSpec
				for _, ep := range svc.EgressPorts {
					k := portKey(uint16(ep.Port), ep.Protocol)
					if seenPorts[k] {
						continue
					}
					seenPorts[k] = true
					ports = append(ports, PortSpec{
						Port:        uint16(ep.Port),
						Protocol:    ep.Protocol,
						Description: "infrastructure egress",
					})
				}
				if len(ports) > 0 {
					sort.Slice(ports, func(i, j int) bool {
						return portKey(ports[i].Port, ports[i].Protocol) < portKey(ports[j].Port, ports[j].Protocol)
					})
					p.EgressRules = append(p.EgressRules, EgressRule{
						ToEntities:  []string{"entity:world"},
						ToCIDRs:     []string{"0.0.0.0/0"},
						ToPorts:     ports,
						Description: "egress infrastructure (synthesized)",
					})
				}
			}
		}
	}

	// Complete observed kube-dns rule or synthesize if needed.
	if !opts.Strict && opts.Config != nil && opts.Config.AlwaysAllowDNS && len(p.EgressRules) > 0 {
		if !completeKubeDNSRule(p.EgressRules, opts.Config) {
			p.EgressRules = append(p.EgressRules, buildDNSEgressRule(workloads, opts.Config.KubeDNSPorts))
			sortEgressRules(p.EgressRules)
		}
	}

	return p
}

// completeKubeDNSRule finds observed egress rules targeting kube-dns (by
// workload ID, namespace, or name matching kube-dns/coredns) and appends any
// missing configured DNS ports to the FIRST matching rule so that every
// workload with an observed kube-dns egress rule carries ALL configured DNS
// ports in a single rule.  Returns true when a matching rule was found (so
// the caller skips synthesis).
func completeKubeDNSRule(rules []EgressRule, cfg *config.Config) bool {
	dnsPorts := config.DefaultKubeDNSPorts
	if cfg != nil && len(cfg.KubeDNSPorts) > 0 {
		dnsPorts = cfg.KubeDNSPorts
	}

	cfgPorts := make(map[string]config.PortSpec)
	for _, ps := range dnsPorts {
		k := portKey(uint16(ps.Port), strings.ToUpper(ps.Protocol))
		cfgPorts[k] = ps
	}

	cfgKeys := make([]string, 0, len(cfgPorts))
	for k := range cfgPorts {
		cfgKeys = append(cfgKeys, k)
	}

	var matched []int
	for i, r := range rules {
		if !isKubeDNSRule(r, cfgPorts) {
			continue
		}
		matched = append(matched, i)
	}
	if len(matched) == 0 {
		return false
	}

	covered := make(map[string]bool)
	for _, idx := range matched {
		for _, rp := range rules[idx].ToPorts {
			k := portKey(rp.Port, strings.ToUpper(rp.Protocol))
			if cfgPorts[k] != (config.PortSpec{}) {
				covered[k] = true
			}
		}
	}

	var missing []PortSpec
	for _, k := range cfgKeys {
		if !covered[k] {
			ps := cfgPorts[k]
			missing = append(missing, PortSpec{
				Port:        uint16(ps.Port),
				Protocol:    ps.Protocol,
				Description: "DNS",
			})
		}
	}

	if len(missing) == 0 {
		return true
	}

	firstIdx := matched[0]
	for _, mp := range missing {
		rules[firstIdx].ToPorts = append(rules[firstIdx].ToPorts, PortSpec{
			Port:        mp.Port,
			Protocol:    mp.Protocol,
			Description: mp.Description,
		})
	}

	sort.Slice(rules[firstIdx].ToPorts, func(i, j int) bool {
		return portKey(rules[firstIdx].ToPorts[i].Port, strings.ToUpper(rules[firstIdx].ToPorts[i].Protocol)) <
			portKey(rules[firstIdx].ToPorts[j].Port, strings.ToUpper(rules[firstIdx].ToPorts[j].Protocol))
	})

	return true
}

// isKubeDNSRule reports whether an egress rule targets kube-dns AND covers
// at least one configured DNS port — the compound predicate matching the
// original hasObservedDNSRuleTargetingKubeDNS semantics.
func isKubeDNSRule(r EgressRule, cfgPorts map[string]config.PortSpec) bool {
	hasOne := false
	for _, rp := range r.ToPorts {
		k := portKey(rp.Port, strings.ToUpper(rp.Protocol))
		if cfgPorts[k] != (config.PortSpec{}) {
			hasOne = true
			break
		}
	}
	if !hasOne {
		return false
	}
	return isKubeDNSRuleTarget(r)
}

// isKubeDNSRuleTarget reports whether an egress rule targets kube-dns by
// workload ID, namespace, or name matching kube-dns/coredns.
func isKubeDNSRuleTarget(r EgressRule) bool {
	for _, tw := range r.ToWorkloads {
		if tw == "kube-system/kube-dns" {
			return true
		}
		if strings.Contains(tw, "kube-system/") {
			name := strings.TrimPrefix(tw, "kube-system/")
			nameLower := strings.ToLower(name)
			if strings.Contains(nameLower, "kube-dns") || strings.Contains(nameLower, "coredns") {
				return true
			}
		}
	}
	for _, ns := range r.ToNamespaces {
		if ns == "kube-system" {
			return true
		}
	}
	return false
}

// buildIngressRules converts ingress aggregation into IngressRule slices.
func buildIngressRules(ingress map[flowKey]*flowEntry, policyNs string, workloadName string, workloads analyze.Workloads, opts BuildOptions) []IngressRule {
	if len(ingress) == 0 {
		return nil
	}

	type peerPortKey struct {
		peer  string
		port  uint16
		proto string
	}

	// Task 10: PublicServices shortcut — if the workload matches a
	// PublicServiceSpec, emit a single match-all rule for those ports
	// and remove them from per-peer/world grouping.
	psMatchedKeys := make(map[flowKey]bool)
	if opts.Config != nil {
		for _, svc := range opts.Config.PublicServices {
			if svc.Namespace == policyNs && svc.Name == workloadName {
				for _, ps := range svc.Ports {
					for k := range ingress {
						if k.port == uint16(ps.Port) && k.proto == ps.Protocol {
							psMatchedKeys[k] = true
						}
					}
				}
			}
		}
	}

	// Collect world ports into a rule with 0.0.0.0/0.
	var worldPorts []PortSpec
	worldSeenPorts := make(map[string]bool)

	// Collect apiserver ports into a rule with "apiserver".
	var apiserverPorts []PortSpec
	apiserverSeenPorts := make(map[string]bool)

	// Collect generic CIDR ports (e.g. /32 node IPs not matching "world"/"apiserver").
	type cidrPortsEntry struct {
		key   peerPortKey
		entry *flowEntry
	}
	cidrPorts := make(map[string][]cidrPortsEntry)

	// Collect per-peer port entries: non-world, non-apiserver, non-cidr, non-public-service flows grouped by peer.
	peerPorts := make(map[string][]struct {
		key peerPortKey
		e   *flowEntry
	})
	var nonWorldPeers []string
	seenPeer := make(map[string]bool)

	// Collect entity bucket: entity sentinel -> set of cidr twins + ports.
	type entityPortsEntry struct {
		kp   peerPortKey
		e    *flowEntry
		cidr string
	}
	entityPorts := make(map[string][]entityPortsEntry)

	for k, v := range ingress {
		// Skip entries matched by PublicServices shortcut.
		if psMatchedKeys[k] {
			continue
		}

		// Entity sentinel check FIRST: reserved peer produces one rule per entity.
		if k.entities != "" {
			entityPorts[k.entities] = append(entityPorts[k.entities], entityPortsEntry{
				kp:   peerPortKey{port: k.port, proto: k.proto},
				e:    v,
				cidr: k.cidr,
			})
			continue
		}

		if k.cidr == "world" {
			pk := portKey(k.port, k.proto)
			if !worldSeenPorts[pk] {
				worldSeenPorts[pk] = true
				desc := countDesc(v.count)
				if v.hasL7DNS {
					desc += " (L7 DNS)"
				}
				if v.hasL7HTTP {
					desc += " (L7 HTTP)"
				}
				worldPorts = append(worldPorts, PortSpec{
					Port:        k.port,
					Protocol:    k.proto,
					Description: desc,
				})
			}
			continue
		}

		if k.cidr == "apiserver" {
			pk := portKey(k.port, k.proto)
			if !apiserverSeenPorts[pk] {
				apiserverSeenPorts[pk] = true
				desc := countDesc(v.count)
				if v.hasL7DNS {
					desc += " (L7 DNS)"
				}
				if v.hasL7HTTP {
					desc += " (L7 HTTP)"
				}
				apiserverPorts = append(apiserverPorts, PortSpec{
					Port:        k.port,
					Protocol:    k.proto,
					Description: desc,
				})
			}
			continue
		}

		// Generic CIDR (e.g. /32 node IPs) — any non-empty cidr not "world"/"apiserver".
		if k.cidr != "" {
			cidrPorts[k.cidr] = append(cidrPorts[k.cidr], cidrPortsEntry{
				key:   peerPortKey{port: k.port, proto: k.proto},
				entry: v,
			})
			continue
		}

		ppk := peerPortKey{peer: k.peer, port: k.port, proto: k.proto}
		peerPorts[k.peer] = append(peerPorts[k.peer], struct {
			key peerPortKey
			e   *flowEntry
		}{key: ppk, e: v})

		if !seenPeer[k.peer] {
			seenPeer[k.peer] = true
			nonWorldPeers = append(nonWorldPeers, k.peer)
		}
	}

	// Sort non-world peers deterministically by selector string.
	sort.Slice(nonWorldPeers, func(i, j int) bool {
		si := srcSelectorFor(policyNs, nonWorldPeers[i], workloads)
		sj := srcSelectorFor(policyNs, nonWorldPeers[j], workloads)
		return si < sj
	})

	var rules []IngressRule

	// Public service rules: emit one rule per matching PublicServiceSpec
	// with FromWorkloads 0.0.0.0/0, containing all matched ports.
	if opts.Config != nil {
		for _, svc := range opts.Config.PublicServices {
			if svc.Namespace == policyNs && svc.Name == workloadName {
				var svcPorts []PortSpec
				seenPorts := make(map[string]bool)
				for _, ps := range svc.Ports {
					pk := portKey(uint16(ps.Port), ps.Protocol)
					if !seenPorts[pk] {
						seenPorts[pk] = true
						svcPorts = append(svcPorts, PortSpec{
							Port:        uint16(ps.Port),
							Protocol:    ps.Protocol,
							Description: "public service",
						})
					}
				}
				if len(svcPorts) > 0 {
					sort.Slice(svcPorts, func(i, j int) bool {
						if svcPorts[i].Port != svcPorts[j].Port {
							return svcPorts[i].Port < svcPorts[j].Port
						}
						return svcPorts[i].Protocol < svcPorts[j].Protocol
					})
					rules = append(rules, IngressRule{
						FromWorkloads: []string{"0.0.0.0/0"},
						Ports:         svcPorts,
						Description:   "public service ingress",
					})
				}
			}
		}
	}

	// Apiserver ingress rule: ipBlock/apiserver sentinel with all observed ports.
	if len(apiserverPorts) > 0 {
		sort.Slice(apiserverPorts, func(i, j int) bool {
			if apiserverPorts[i].Port != apiserverPorts[j].Port {
				return apiserverPorts[i].Port < apiserverPorts[j].Port
			}
			return apiserverPorts[i].Protocol < apiserverPorts[j].Protocol
		})
		rules = append(rules, IngressRule{
			FromWorkloads: []string{"apiserver"},
			Ports:         apiserverPorts,
			Description:   "apiserver ingress",
		})
	}

	// World ingress rule: ipBlock 0.0.0.0/0 with all observed ports.
	if len(worldPorts) > 0 {
		sort.Slice(worldPorts, func(i, j int) bool {
			if worldPorts[i].Port != worldPorts[j].Port {
				return worldPorts[i].Port < worldPorts[j].Port
			}
			return worldPorts[i].Protocol < worldPorts[j].Protocol
		})
		rules = append(rules, IngressRule{
			FromWorkloads: []string{"0.0.0.0/0"},
			Ports:         worldPorts,
			Description:   "world ingress",
		})
	}

	// Entity rules: one IngressRule per entity sentinel, carrying BOTH the
	// CIDR twin (FromWorkloads) and the entity sentinel (FromEntities).
	if len(entityPorts) > 0 {
		entityKeys := make([]string, 0, len(entityPorts))
		for k := range entityPorts {
			entityKeys = append(entityKeys, k)
		}
		sort.Strings(entityKeys)
		for _, ek := range entityKeys {
			entries := entityPorts[ek]
			seenCidrs := make(map[string]bool)
			for _, ep := range entries {
				if ep.cidr != "" {
					cidrTwin := ep.cidr
					if cidrTwin == "world" {
						cidrTwin = "0.0.0.0/0"
					}
					seenCidrs[cidrTwin] = true
				}
			}
			twinCidrs := make([]string, 0, len(seenCidrs))
			for c := range seenCidrs {
				twinCidrs = append(twinCidrs, c)
			}
			sort.Strings(twinCidrs)

			// Dedup ports by (proto, port) keeping first-seen.
			seenPortKeys := make(map[string]bool)
			var portSpecs []PortSpec
			for _, ep := range entries {
				pk := portKey(ep.kp.port, ep.kp.proto)
				if seenPortKeys[pk] {
					continue
				}
				seenPortKeys[pk] = true
				desc := countDesc(ep.e.count)
				if ep.e.hasL7DNS {
					desc += " (L7 DNS)"
				}
				if ep.e.hasL7HTTP {
					desc += " (L7 HTTP)"
				}
				portSpecs = append(portSpecs, PortSpec{
					Port:        ep.kp.port,
					Protocol:    ep.kp.proto,
					Description: desc,
				})
			}
			sort.Slice(portSpecs, func(i, j int) bool {
				if portSpecs[i].Port != portSpecs[j].Port {
					return portSpecs[i].Port < portSpecs[j].Port
				}
				return portSpecs[i].Protocol < portSpecs[j].Protocol
			})
			rules = append(rules, IngressRule{
				FromWorkloads: twinCidrs,
				FromEntities:  []string{ek},
				Ports:         portSpecs,
				Description:   "ingress",
			})
		}
	}

	// Generic CIDR peers: emit one IngressRule per sorted CIDR key.
	if len(cidrPorts) > 0 {
		cidrKeys := make([]string, 0, len(cidrPorts))
		for k := range cidrPorts {
			cidrKeys = append(cidrKeys, k)
		}
		sort.Strings(cidrKeys)
		for _, ck := range cidrKeys {
			entries := cidrPorts[ck]
			// Dedup ports by (proto, port) keeping first-seen.
			seenPortKeys := make(map[string]bool)
			var portSpecs []PortSpec
			for _, e := range entries {
				kk := e.key
				pk := portKey(kk.port, kk.proto)
				if seenPortKeys[pk] {
					continue
				}
				seenPortKeys[pk] = true
				desc := countDesc(e.entry.count)
				if e.entry.hasL7DNS {
					desc += " (L7 DNS)"
				}
				if e.entry.hasL7HTTP {
					desc += " (L7 HTTP)"
				}
				portSpecs = append(portSpecs, PortSpec{
					Port:        kk.port,
					Protocol:    kk.proto,
					Description: desc,
				})
			}
			sort.Slice(portSpecs, func(i, j int) bool {
				if portSpecs[i].Port != portSpecs[j].Port {
					return portSpecs[i].Port < portSpecs[j].Port
				}
				return portSpecs[i].Protocol < portSpecs[j].Protocol
			})
			rules = append(rules, IngressRule{
				FromWorkloads: []string{ck},
				Ports:         portSpecs,
				Description:   "ingress",
			})
		}
	}

	// One IngressRule per non-world peer, scoped to that peer's ports only.
	for _, peer := range nonWorldPeers {
		entries := peerPorts[peer]
		sel := srcSelectorFor(policyNs, peer, workloads)

		// Dedup ports by (proto, port) keeping the first seen entry (which has the count).
		seenPortKeys := make(map[string]bool)
		var portSpecs []PortSpec
		for _, e := range entries {
			pk := portKey(e.key.port, e.key.proto)
			if !seenPortKeys[pk] {
				seenPortKeys[pk] = true
				desc := countDesc(e.e.count)
				if e.e.hasL7DNS {
					desc += " (L7 DNS)"
				}
				if e.e.hasL7HTTP {
					desc += " (L7 HTTP)"
				}
				portSpecs = append(portSpecs, PortSpec{
					Port:        e.key.port,
					Protocol:    e.key.proto,
					Description: desc,
				})
			}
		}

		// Sort ports by port then protocol.
		sort.Slice(portSpecs, func(i, j int) bool {
			if portSpecs[i].Port != portSpecs[j].Port {
				return portSpecs[i].Port < portSpecs[j].Port
			}
			return portSpecs[i].Protocol < portSpecs[j].Protocol
		})

		rules = append(rules, IngressRule{
			FromWorkloads: []string{sel},
			Ports:         portSpecs,
			Description:   "ingress",
		})
	}

	return rules
}

// buildEgressRules converts egress aggregation into EgressRule slices.
// Each unique (peer, cidr) combo emits its own rule with peer-scoped ports.
func buildEgressRules(egress map[flowKey]*flowEntry, policyNs string, workloads analyze.Workloads) []EgressRule {
	if len(egress) == 0 {
		return nil
	}

	// Group entries by peer (toWorkloads) and by CIDR (toCIDRs).
	type keyedPorts struct {
		key   string
		ports []PortSpec
		hasL7 string
	}
	peerMap := make(map[string]*keyedPorts) // peerID -> ports
	cidrMap := make(map[string]*keyedPorts) // cidrID -> ports
	// entityMap: entity sentinel -> set of cidr twins + ports
	type entityKeyedPorts struct {
		cidrsSet map[string]bool
		ports    []PortSpec
	}
	entityMap := make(map[string]*entityKeyedPorts)

	for k, v := range egress {
		// Entity sentinel check FIRST: reserved peer produces one rule per entity.
		if k.entities != "" {
			if ep, ok := entityMap[k.entities]; ok {
				ep.ports = appendIfNeeded(ep.ports, k.port, k.proto, v.count, v.hasL7DNS, v.hasL7HTTP)
				if k.cidr != "" {
					cidrTwin := k.cidr
					if cidrTwin == "world" {
						cidrTwin = "0.0.0.0/0"
					}
					ep.cidrsSet[cidrTwin] = true
				}
			} else {
				var l7 string
				if v.hasL7DNS {
					l7 = " (L7 DNS)"
				} else if v.hasL7HTTP {
					l7 = " (L7 HTTP)"
				}
				cs := make(map[string]bool)
				if k.cidr != "" {
					cidrTwin := k.cidr
					if cidrTwin == "world" {
						cidrTwin = "0.0.0.0/0"
					}
					cs[cidrTwin] = true
				}
				entityMap[k.entities] = &entityKeyedPorts{
					cidrsSet: cs,
					ports:    []PortSpec{{Port: k.port, Protocol: k.proto, Description: countDesc(v.count) + l7}},
				}
			}
		} else if k.cidr == "" {
			// Peer-based rule.
			if pp, ok := peerMap[k.peer]; ok {
				pp.ports = appendIfNeeded(pp.ports, k.port, k.proto, v.count, v.hasL7DNS, v.hasL7HTTP)
			} else {
				var l7 string
				if v.hasL7DNS {
					l7 = " (L7 DNS)"
				} else if v.hasL7HTTP {
					l7 = " (L7 HTTP)"
				}
				peerMap[k.peer] = &keyedPorts{
					key:   k.peer,
					ports: []PortSpec{{Port: k.port, Protocol: k.proto, Description: countDesc(v.count) + l7}},
					hasL7: l7,
				}
			}
		} else {
			// CIDR-based rule (world, apiserver, etc).
			cidrStr := k.cidr
			if cidrStr == "world" {
				cidrStr = "0.0.0.0/0"
			}
			if cp, ok := cidrMap[cidrStr]; ok {
				cp.ports = appendIfNeeded(cp.ports, k.port, k.proto, v.count, v.hasL7DNS, v.hasL7HTTP)
			} else {
				var l7 string
				if v.hasL7DNS {
					l7 = " (L7 DNS)"
				} else if v.hasL7HTTP {
					l7 = " (L7 HTTP)"
				}
				cidrMap[cidrStr] = &keyedPorts{
					key:   cidrStr,
					ports: []PortSpec{{Port: k.port, Protocol: k.proto, Description: countDesc(v.count) + l7}},
					hasL7: l7,
				}
			}
		}
	}

	var rules []EgressRule

	// Build per-peer rules.
	for pk := range peerMap {
		pp := peerMap[pk]
		if len(pp.ports) == 0 {
			continue
		}
		sel := srcSelectorFor(policyNs, pp.key, workloads)
		rules = append(rules, EgressRule{
			ToWorkloads: []string{sel},
			ToPorts:     pp.ports,
			Description: "egress",
		})
	}

	// Build world/CIDR rules.
	for ci := range cidrMap {
		cp := cidrMap[ci]
		if len(cp.ports) == 0 {
			continue
		}
		rules = append(rules, EgressRule{
			ToCIDRs:     []string{cp.key},
			ToPorts:     cp.ports,
			Description: "egress",
		})
	}

	// Entity egress rules: one rule per entity sentinel, carrying BOTH the
	// CIDR twin (ToCIDRs) and the entity sentinel (ToEntities).
	if len(entityMap) > 0 {
		entityKeys := make([]string, 0, len(entityMap))
		for k := range entityMap {
			entityKeys = append(entityKeys, k)
		}
		sort.Strings(entityKeys)
		for _, ek := range entityKeys {
			ep := entityMap[ek]
			if len(ep.ports) == 0 {
				continue
			}
			// Sorted CIDR twins.
			twinCidrs := make([]string, 0, len(ep.cidrsSet))
			for c := range ep.cidrsSet {
				twinCidrs = append(twinCidrs, c)
			}
			sort.Strings(twinCidrs)
			rules = append(rules, EgressRule{
				ToCIDRs:     twinCidrs,
				ToEntities:  []string{ek},
				ToPorts:     ep.ports,
				Description: "egress",
			})
		}
	}

	// Sort rules deterministically (ToWorkloads before ToNamespaces before ToEntities before ToCIDRs, then by first element).
	sortEgressRules(rules)

	return rules
}

// findKubeDNSWorkload returns the first kube-dns workload ID in the
// workloads map, searching kube-system namespace for names containing
// "kube-dns" or "coredns" (case-insensitive), or any workload with a
// label "k8s-app" matching "kube-dns" (case-insensitive).
// Returns "" when no such workload is found.
func findKubeDNSWorkload(workloads analyze.Workloads) string {
	const (
		k8sAppName      = "k8s-app"
		kubeDNSLabelVal = "kube-dns"
	)
	for _, id := range workloads.SortedIDs() {
		wd, ok := workloads[analyze.WorkloadID(id)]
		if !ok {
			continue
		}
		if wd.Namespace != "kube-system" {
			continue
		}
		nameLower := strings.ToLower(wd.Name)
		if strings.Contains(nameLower, "kube-dns") || strings.Contains(nameLower, "coredns") {
			return id
		}
		if lbl, ok := wd.Labels[k8sAppName]; ok && strings.EqualFold(lbl, kubeDNSLabelVal) {
			return id
		}
	}
	return ""
}

// buildDNSEgressRule builds a DNS egress rule. If a kube-dns workload exists
// in workloads it targets that workload by ID; otherwise it targets the
// kube-system namespace. Ports come from dnsPorts or default to UDP/53 + TCP/53.
func buildDNSEgressRule(workloads analyze.Workloads, dnsPorts []config.PortSpec) EgressRule {
	ports := []PortSpec{
		{Port: 53, Protocol: "UDP", Description: "DNS"},
		{Port: 53, Protocol: "TCP", Description: "DNS"},
	}
	if len(dnsPorts) > 0 {
		ports = make([]PortSpec, 0, len(dnsPorts))
		for _, ps := range dnsPorts {
			ports = append(ports, PortSpec{Port: uint16(ps.Port), Protocol: ps.Protocol, Description: "DNS"})
		}
	}

	kubeDNSID := findKubeDNSWorkload(workloads)
	if kubeDNSID != "" {
		return EgressRule{
			ToWorkloads: []string{kubeDNSID},
			ToPorts:     ports,
			Description: "egress DNS (always-allow)",
		}
	}
	return EgressRule{
		ToNamespaces: []string{"kube-system"},
		ToPorts:      ports,
		Description:  "egress DNS (always-allow)",
	}
}

// sortEgressRules sorts an egress rules slice deterministically: rules with
// ToWorkloads first, then ToNamespaces, then ToEntities, then ToCIDRs — each
// partition sorted by the first element of its target field, then by
// Description.
func sortEgressRules(rules []EgressRule) {
	sort.Slice(rules, func(i, j int) bool {
		iW, jW := len(rules[i].ToWorkloads) > 0, len(rules[j].ToWorkloads) > 0
		if iW != jW {
			return iW
		}
		if iW {
			if rules[i].ToWorkloads[0] != rules[j].ToWorkloads[0] {
				return rules[i].ToWorkloads[0] < rules[j].ToWorkloads[0]
			}
		} else if len(rules[i].ToNamespaces) > 0 || len(rules[j].ToNamespaces) > 0 {
			iN, jN := len(rules[i].ToNamespaces) > 0, len(rules[j].ToNamespaces) > 0
			if iN != jN {
				return iN
			}
			if rules[i].ToNamespaces[0] != rules[j].ToNamespaces[0] {
				return rules[i].ToNamespaces[0] < rules[j].ToNamespaces[0]
			}
			return rules[i].Description < rules[j].Description
		} else if len(rules[i].ToEntities) > 0 && len(rules[j].ToEntities) > 0 {
			if rules[i].ToEntities[0] != rules[j].ToEntities[0] {
				return rules[i].ToEntities[0] < rules[j].ToEntities[0]
			}
			return rules[i].Description < rules[j].Description
		} else if len(rules[i].ToEntities) > 0 {
			return true
		} else if len(rules[j].ToEntities) > 0 {
			return false
		} else if len(rules[i].ToCIDRs) > 0 && len(rules[j].ToCIDRs) > 0 {
			if rules[i].ToCIDRs[0] != rules[j].ToCIDRs[0] {
				return rules[i].ToCIDRs[0] < rules[j].ToCIDRs[0]
			}
		}
		return rules[i].Description < rules[j].Description
	})
}

// appendIfNeeded deduplicates ports by key and appends a new port/protocol
// entry with its description, or increments count if already present.
func appendIfNeeded(ports []PortSpec, port uint16, proto string, count int, hasL7DNS, hasL7HTTP bool) []PortSpec {
	k := portKey(port, proto)
	for i, p := range ports {
		if portKey(p.Port, p.Protocol) == k {
			var l7 string
			if hasL7DNS {
				l7 = " (L7 DNS)"
			} else if hasL7HTTP {
				l7 = " (L7 HTTP)"
			}
			ports[i].Description = countDesc(count) + l7
			return ports
		}
	}
	var l7 string
	if hasL7DNS {
		l7 = " (L7 DNS)"
	} else if hasL7HTTP {
		l7 = " (L7 HTTP)"
	}
	return append(ports, PortSpec{Port: port, Protocol: proto, Description: countDesc(count) + l7})
}

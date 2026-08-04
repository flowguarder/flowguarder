// Package policy generates Kubernetes NetworkPolicy and CiliumNetworkPolicy
// manifests from observed network flow patterns.
package policy

import (
	"log"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/flowguarder/flowguarder/pkg/anomaly"
	"github.com/flowguarder/flowguarder/pkg/analyze"
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
	// Ports lists the permitted L4 ports.
	Ports []PortSpec
	// Description is a human-readable note for this rule.
	Description string
}

// EgressRule represents a single egress rule derived from observed traffic.
type EgressRule struct {
	// ToWorkloads lists workload selectors permitted to receive traffic.
	ToWorkloads []string
	// ToCIDRs lists permitted CIDR ranges (for world egress).
	ToCIDRs []string
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
	peer  string
	port  uint16
	proto string
	cidr  string // "world" for public egress, "" for pod-pod
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
	// Filter anomalies.
	if len(opts.ExcludeAnomalyTypes) > 0 {
		anomalies = nil
		for _, a := range anomalies {
			skip := false
			for _, et := range opts.ExcludeAnomalyTypes {
				if a.Type == et {
					skip = true
					break
				}
			}
			if !skip {
				anomalies = append(anomalies, a)
			}
		}
	}

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
			dstIP := net.ParseIP(f.Destination.IP)
			srcIP := net.ParseIP(f.Source.IP)
			isWorldIngress := (dstIP != nil && srcIP != nil && analyze.IsPublicIP(srcIP) && analyze.IsPrivateIP(dstIP, nil)) ||
				isSyntheticEndpoint(f.Source) ||
				f.PeerType == flow.KubeAPIServer
			if isWorldIngress {
				cidr = "world"
				if opts.Config != nil {
					for _, ps := range opts.Config.ApiserverIngressPorts {
						if f.Layer4.DestPort == uint16(ps.Port) && string(f.Layer4.Protocol) == ps.Protocol {
							cidr = "apiserver"
							break
						}
					}
				}
			}
			k := flowKey{peer: srcKey, port: port, proto: proto, cidr: cidr}
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
			dstIP := net.ParseIP(f.Destination.IP)
			srcIP := net.ParseIP(f.Source.IP)
			isWorldEgress := (dstIP != nil && srcIP != nil && analyze.IsPublicIP(dstIP) && analyze.IsPrivateIP(srcIP, nil)) ||
				isSyntheticEndpoint(f.Destination) ||
				f.PeerType == flow.KubeAPIServer
			if isWorldEgress {
				cidr = "world"
				if opts.Config != nil {
					for _, ps := range opts.Config.ApiserverEgressPorts {
						if f.Layer4.DestPort == uint16(ps.Port) && string(f.Layer4.Protocol) == ps.Protocol {
							cidr = "apiserver"
							break
						}
					}
				}
			}
			k := flowKey{peer: dstKey, port: port, proto: proto, cidr: cidr}
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
				ik := flowKey{peer: srcKey, port: port, proto: proto, cidr: ""}
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
					if f.L7.Type == "http" || f.L7.Type == "tls" {
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

// isSyntheticEndpoint returns true when the endpoint resolves to a synthetic
// workload (pvt, pub, or unknown "-"). Used as a fallback for world CIDR
// detection when the Goldmane parser sets all flow IPs to 0.0.0.0.
func isSyntheticEndpoint(ep flow.Endpoint) bool {
	wl := analyze.ResolveWorkload(ep)
	return wl.Name == "pvt" || wl.Name == "pub" || wl.Name == "-"
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

	// Add default-deny stub when requested.
	if opts.DefaultDeny && len(p.IngressRules) > 0 {
		p.IngressRules = append(p.IngressRules, IngressRule{Description: "default deny-all ingress"})
	}

	return p
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

	// Collect per-peer port entries: non-world, non-apiserver, non-public-service flows grouped by peer.
	peerPorts := make(map[string][]struct {
		key peerPortKey
		e   *flowEntry
	})
	var nonWorldPeers []string
	seenPeer := make(map[string]bool)

	for k, v := range ingress {
		// Skip entries matched by PublicServices shortcut.
		if psMatchedKeys[k] {
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
		key    string
		ports  []PortSpec
		hasL7  string
	}
	peerMap := make(map[string]*keyedPorts)  // peerID -> ports
	cidrMap := make(map[string]*keyedPorts)  // cidrID -> ports

	for k, v := range egress {
		if k.cidr == "" {
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

	// Sort rules deterministically (ToWorkloads before ToCIDRs, then by first element).
	sort.Slice(rules, func(i, j int) bool {
		iW, jW := len(rules[i].ToWorkloads) > 0, len(rules[j].ToWorkloads) > 0
		if iW != jW {
			return iW // ToWorkloads rules first
		}
		if iW {
			if rules[i].ToWorkloads[0] != rules[j].ToWorkloads[0] {
				return rules[i].ToWorkloads[0] < rules[j].ToWorkloads[0]
			}
		} else {
			if rules[i].ToCIDRs[0] != rules[j].ToCIDRs[0] {
				return rules[i].ToCIDRs[0] < rules[j].ToCIDRs[0]
			}
		}
		return rules[i].Description < rules[j].Description
	})

	return rules
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

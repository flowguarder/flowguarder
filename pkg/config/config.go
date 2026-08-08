// Package config provides YAML configuration loading, validation, and
// sensible defaults for the flowguarder CLI.
package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Default values.
const (
	defaultRareFlowThreshold     = 0.001
	defaultPortScanThreshold     = 10
	defaultPortScanWindowSeconds = 10
	defaultAsymmetricRatio       = 10.0
)

// DefaultClusterCIDRsStrings are the RFC 1918 / CGNAT / RFC 4193 (ULA) ranges
// that the classifier considers "internal", stored as strings for YAML parsing.
var DefaultClusterCIDRsStrings = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"fd00::/8",
	"100.64.0.0/10",
}

// DefaultAPIServerCIDRsStrings are assumed internal for kube-apiserver classification.
var DefaultAPIServerCIDRsStrings = []string{
	"10.96.0.0/12",
}

// DefaultKubeDNSPorts are the well-known DNS ports for Kubernetes.
var DefaultKubeDNSPorts = []PortSpec{
	{Protocol: "UDP", Port: 53},
	{Protocol: "TCP", Port: 53},
}

// DefaultExcludedNamespaces are infrastructure namespaces to skip.
var DefaultExcludedNamespaces = []string{
	"kube-system",
	"calico-system",
	"tigera-operator",
}

// DefaultApiserverIngressPorts are the well-known kube-apiserver ports.
var DefaultApiserverIngressPorts = []PortSpec{
	{Protocol: "TCP", Port: 9443},
	{Protocol: "TCP", Port: 8443},
	{Protocol: "TCP", Port: 5443},
	{Protocol: "TCP", Port: 6443},
}

var DefaultApiserverEgressPorts = []PortSpec{
	{Protocol: "TCP", Port: 6443},
}

// DefaultPublicServices are built-in services that should be classified as public.
var DefaultPublicServices = []PublicServiceSpec{
	{
		Namespace: "kube-system",
		Name:      "kube-dns",
		Ports:     []PortSpec{{Protocol: "UDP", Port: 53}, {Protocol: "TCP", Port: 53}},
	},
	{
		Namespace: "kube-system",
		Name:      "metrics-server",
		Ports:     []PortSpec{{Protocol: "TCP", Port: 4443}, {Protocol: "TCP", Port: 10250}},
	},
}

// Profile defines per-namespace traffic rules.
type Profile struct {
	// AllowedTargets is a list of "namespace/name:port/proto" patterns that are
	// always permitted regardless of classification.
	AllowedTargets []string `yaml:"allowed_targets,omitempty"`
	// DisallowedTargets is a list of "namespace/name:port/proto" patterns that
	// must never be allowed.
	DisallowedTargets []string `yaml:"disallowed_targets,omitempty"`
	// RequiredLabels are key names that must be present on pods in the namespace.
	RequiredLabels []string `yaml:"required_labels,omitempty"`
}

// PortSpec describes a single network port with protocol.
type PortSpec struct {
	Protocol string `yaml:"protocol"`
	Port     int    `yaml:"port"`
}

// PublicServiceSpec describes a Kubernetes service whose traffic should be
// classified as public egress.
type PublicServiceSpec struct {
	Namespace        string     `yaml:"namespace,omitempty"`
	Name             string     `yaml:"name,omitempty"`
	Ports            []PortSpec `yaml:"ports,omitempty"`
	EgressPorts      []PortSpec `yaml:"egress_ports,omitempty"`
	EgressAllowWorld bool       `yaml:"egress_allow_world,omitempty"`
}

type WorkloadSelector struct {
	Namespace string `yaml:"namespace,omitempty"`
	Name      string `yaml:"name,omitempty"`
}

// Config holds all tunable parameters for flow analysis.
type Config struct {
	// ClusterCIDRs lists IP ranges considered internal Kubernetes cluster
	// addressing (RFC 1918 + CGNAT + ULA).
	ClusterCIDRs []*net.IPNet `yaml:"cluster_cidrs,omitempty"`
	// APIServerCIDRs are ranges assumed to carry kube-apiserver traffic.
	APIServerCIDRs []*net.IPNet `yaml:"apiserver_cidrs,omitempty"`
	// ExcludedNamespaces are namespaces whose flows are ignored.
	ExcludedNamespaces []string `yaml:"excluded_namespaces,omitempty"`
	// KubeDNSPorts are well-known DNS ports for classification.
	KubeDNSPorts []PortSpec `yaml:"kube_dns_ports,omitempty"`
	// RareFlowThreshold is the percentile below which a pattern is
	// considered a rare-flow anomaly (0..1).
	RareFlowThreshold float64 `yaml:"rare_flow_threshold,omitempty"`
	// PortScanThreshold is the number of distinct destination ports
	// within WindowSeconds that triggers a port-scan alert.
	PortScanThreshold int `yaml:"port_scan_threshold,omitempty"`
	// PortScanWindowSeconds is the time window for port-scan detection.
	PortScanWindowSeconds int `yaml:"port_scan_window_seconds,omitempty"`
	// AsymmetricRatio is the egress/ingress ratio threshold. If
	// egress_bytes / max(ingress_bytes, 1) >= this value, flag as
	// asymmetric-traffic anomaly (default 10.0).
	AsymmetricRatio float64 `yaml:"asymmetric_ratio,omitempty"`
	// PublicEgressKnownGood is a set of domain/service names known to be
	// legitimate egress endpoints (e.g. Docker Hub, GitHub).
	PublicEgressKnownGood []string `yaml:"public_egress_known_good,omitempty"`
	// AllowedNamespacePairs maps a source namespace to a list of allowed
	// destination namespaces.
	AllowedNamespacePairs map[string][]string `yaml:"allowed_namespace_pairs,omitempty"`
	// PerNamespaceProfiles holds per-namespace Profile configurations keyed by namespace.
	PerNamespaceProfiles map[string]Profile `yaml:"per_namespace_profiles,omitempty"`
	// KnownGoodExternalEndpoints is a list of fully-qualified domain names or
	// IPs that are confirmed-good external egress targets.
	KnownGoodExternalEndpoints []string `yaml:"known_good_external_endpoints,omitempty"`
	// PublicEgressAllowlistCIDRs are public (non-RFC-1918) CIDR ranges that
	// are considered legitimate.
	PublicEgressAllowlistCIDRs []*net.IPNet `yaml:"public_egress_allowlist_cidrs,omitempty"`
	// ApiserverIngressPorts are well-known ingress ports for kube-apiserver
	// classification.
	ApiserverIngressPorts []PortSpec `yaml:"apiserver_ingress_ports,omitempty"`
	// ApiserverEgressPorts are well-known egress ports to kube-apiserver.
	ApiserverEgressPorts []PortSpec `yaml:"apiserver_egress_ports,omitempty"`
	// PublicServices lists Kubernetes services whose traffic should be
	// classified as public egress.
	PublicServices []PublicServiceSpec `yaml:"public_services,omitempty"`
	// ApiserverWorkloadSelector identifies the workload that should be treated as
	// kube-apiserver for apiserver-port override. When nil, only reserved:kube-apiserver
	// peers trigger the override.
	ApiserverWorkloadSelector *WorkloadSelector `yaml:"apiserver_workload_selector,omitempty"`
	// NodeCIDRs are optional IP ranges covering cluster nodes. When set, NetworkPolicy
	// renders these alongside inferred /32 node IPs for apiserver rules.
	NodeCIDRs []string `yaml:"node_cidrs,omitempty"`
	// AlwaysAllowDNS is true when DNS traffic to kube-dns is always allowed.
	AlwaysAllowDNS bool `yaml:"always_allow_dns,omitempty"`
}

// Default returns a Config populated with built-in defaults.
// Panics on invalid default CIDRs (should never happen).
func Default() Config {
	clusterCIDRs, _ := cidrStringsToIPNet(DefaultClusterCIDRsStrings, "cluster_cidrs")
	apiserverCIDRs, _ := cidrStringsToIPNet(DefaultAPIServerCIDRsStrings, "apiserver_cidrs")
	c := Config{
		ClusterCIDRs:               clusterCIDRs,
		APIServerCIDRs:             apiserverCIDRs,
		ExcludedNamespaces:         make([]string, len(DefaultExcludedNamespaces)),
		KubeDNSPorts:               make([]PortSpec, len(DefaultKubeDNSPorts)),
		RareFlowThreshold:          defaultRareFlowThreshold,
		PortScanThreshold:          defaultPortScanThreshold,
		PortScanWindowSeconds:      defaultPortScanWindowSeconds,
		AsymmetricRatio:            defaultAsymmetricRatio,
		AllowedNamespacePairs:      make(map[string][]string),
		PerNamespaceProfiles:       make(map[string]Profile),
		PublicEgressKnownGood:      []string{},
		KnownGoodExternalEndpoints: []string{},
		PublicEgressAllowlistCIDRs: []*net.IPNet{},
		ApiserverIngressPorts:      make([]PortSpec, len(DefaultApiserverIngressPorts)),
		ApiserverEgressPorts:       make([]PortSpec, len(DefaultApiserverEgressPorts)),
		PublicServices:             make([]PublicServiceSpec, len(DefaultPublicServices)),
		ApiserverWorkloadSelector:  &WorkloadSelector{Namespace: "kube-system", Name: "kube-apiserver"},
		NodeCIDRs:                  []string{},
		AlwaysAllowDNS:             true,
	}
	copy(c.ExcludedNamespaces, DefaultExcludedNamespaces)
	copy(c.KubeDNSPorts, DefaultKubeDNSPorts)
	copy(c.ApiserverIngressPorts, DefaultApiserverIngressPorts)
	copy(c.ApiserverEgressPorts, DefaultApiserverEgressPorts)
	copy(c.PublicServices, DefaultPublicServices)
	return c
}

// Merge fills zero-valued fields in c with values from defaults.
// Only fields that are nil, nil-mapped, empty slices, or zero-valued
// scalars are replaced.
func (c *Config) Merge(defaults Config) {
	if len(c.ClusterCIDRs) == 0 {
		c.ClusterCIDRs = defaults.ClusterCIDRs
	}
	if len(c.APIServerCIDRs) == 0 {
		c.APIServerCIDRs = defaults.APIServerCIDRs
	}
	if len(c.ExcludedNamespaces) == 0 {
		c.ExcludedNamespaces = defaults.ExcludedNamespaces
	}
	if len(c.KubeDNSPorts) == 0 {
		c.KubeDNSPorts = defaults.KubeDNSPorts
	}
	if c.RareFlowThreshold == 0 {
		c.RareFlowThreshold = defaults.RareFlowThreshold
	}
	if c.PortScanThreshold == 0 {
		c.PortScanThreshold = defaults.PortScanThreshold
	}
	if c.PortScanWindowSeconds == 0 {
		c.PortScanWindowSeconds = defaults.PortScanWindowSeconds
	}
	if c.AsymmetricRatio == 0 {
		c.AsymmetricRatio = defaults.AsymmetricRatio
	}
	if len(c.PublicEgressKnownGood) == 0 {
		c.PublicEgressKnownGood = defaults.PublicEgressKnownGood
	}
	if len(c.AllowedNamespacePairs) == 0 {
		c.AllowedNamespacePairs = make(map[string][]string)
		for ns, targets := range defaults.AllowedNamespacePairs {
			c.AllowedNamespacePairs[ns] = targets
		}
	}
	if len(c.PerNamespaceProfiles) == 0 {
		c.PerNamespaceProfiles = make(map[string]Profile)
		for ns, p := range defaults.PerNamespaceProfiles {
			c.PerNamespaceProfiles[ns] = p
		}
	}
	if len(c.KnownGoodExternalEndpoints) == 0 {
		c.KnownGoodExternalEndpoints = defaults.KnownGoodExternalEndpoints
	}
	if len(c.PublicEgressAllowlistCIDRs) == 0 {
		c.PublicEgressAllowlistCIDRs = defaults.PublicEgressAllowlistCIDRs
	}
	if len(c.ApiserverIngressPorts) == 0 {
		c.ApiserverIngressPorts = defaults.ApiserverIngressPorts
	}
	if len(c.ApiserverEgressPorts) == 0 {
		c.ApiserverEgressPorts = defaults.ApiserverEgressPorts
	}
	if len(c.PublicServices) == 0 {
		c.PublicServices = defaults.PublicServices
	}
	if c.ApiserverWorkloadSelector == nil {
		c.ApiserverWorkloadSelector = defaults.ApiserverWorkloadSelector
	}
	if len(c.NodeCIDRs) == 0 {
		c.NodeCIDRs = defaults.NodeCIDRs
	}
	// AlwaysAllowDNS is intentionally not merged: toConfig() already applies the
	// default (true) when the YAML key is absent, and Merge must not clobber an
	// explicit `always_allow_dns: false` (false is the zero value).
}

// Load reads a YAML config file at the given path. If path is empty,
// it returns Default(). After loading, Merge(defaults) is applied and
// Validate() is run.
func Load(path string) (Config, error) {
	if path == "" {
		return Default(), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %q: %w", path, err)
	}

	// Unmarshal into a raw intermediate to handle CIDR strings properly.
	var raw configRaw
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return Config{}, fmt.Errorf("parse config %q: %w", path, err)
	}

	c, toErr := raw.toConfig()
	if toErr != nil {
		return Config{}, fmt.Errorf("parse config %q: %w", path, toErr)
	}

	c.Merge(Default())

	if err := c.Validate(); err != nil {
		return Config{}, fmt.Errorf("validate config %q: %w", path, err)
	}

	return c, nil
}

// Validate checks that all non-zero config values are sensible.
func (c Config) Validate() error {
	if c.RareFlowThreshold < 0 {
		return fmt.Errorf("rare_flow_threshold must be >= 0, got %f", c.RareFlowThreshold)
	}
	if c.RareFlowThreshold > 1 {
		return fmt.Errorf("rare_flow_threshold must be <= 1, got %f", c.RareFlowThreshold)
	}
	if c.PortScanThreshold < 0 {
		return fmt.Errorf("port_scan_threshold must be >= 0, got %d", c.PortScanThreshold)
	}
	if c.PortScanWindowSeconds < 0 {
		return fmt.Errorf("port_scan_window_seconds must be >= 0, got %d", c.PortScanWindowSeconds)
	}
	if c.AsymmetricRatio < 1.0 {
		return fmt.Errorf("asymmetric_ratio must be >= 1.0, got %f", c.AsymmetricRatio)
	}

	for i, cidr := range c.ClusterCIDRs {
		if cidr == nil {
			return fmt.Errorf("cluster_cidrs[%d] is nil", i)
		}
	}
	for i, cidr := range c.APIServerCIDRs {
		if cidr == nil {
			return fmt.Errorf("apiserver_cidrs[%d] is nil", i)
		}
	}
	for i, cidr := range c.PublicEgressAllowlistCIDRs {
		if cidr == nil {
			return fmt.Errorf("public_egress_allowlist_cidrs[%d] is nil", i)
		}
	}

	for _, ps := range c.KubeDNSPorts {
		if ps.Port < 0 || ps.Port > 65535 {
			return fmt.Errorf("invalid kube_dns_port: %d (must be 0-65535)", ps.Port)
		}
	}

	for i, ps := range c.ApiserverIngressPorts {
		if ps.Port < 0 || ps.Port > 65535 {
			return fmt.Errorf("invalid apiserver_ingress_ports[%d]: %d (must be 0-65535)", i, ps.Port)
		}
	}

	for i, ps := range c.ApiserverEgressPorts {
		if ps.Port < 0 || ps.Port > 65535 {
			return fmt.Errorf("invalid apiserver_egress_ports[%d]: %d (must be 0-65535)", i, ps.Port)
		}
	}

	for _, svc := range c.PublicServices {
		for j, ps := range svc.Ports {
			if ps.Port < 0 || ps.Port > 65535 {
				return fmt.Errorf("invalid public_services[%s/%s].ports[%d]: %d (must be 0-65535)",
					svc.Namespace, svc.Name, j, ps.Port)
			}
		}
		for j, ps := range svc.EgressPorts {
			if ps.Protocol == "" {
				return fmt.Errorf("invalid public_services[%s/%s].egress_ports[%d]: protocol must not be empty",
					svc.Namespace, svc.Name, j)
			}
			if ps.Port < 1 || ps.Port > 65535 {
				return fmt.Errorf("invalid public_services[%s/%s].egress_ports[%d]: %d (must be 1-65535)",
					svc.Namespace, svc.Name, j, ps.Port)
			}
		}
		if svc.EgressAllowWorld && len(svc.Ports) == 0 {
			return fmt.Errorf("public_services[%s/%s]: egress_allow_world requires at least one port", svc.Namespace, svc.Name)
		}
	}

	if c.ApiserverWorkloadSelector != nil {
		if c.ApiserverWorkloadSelector.Namespace == "" || c.ApiserverWorkloadSelector.Name == "" {
			return fmt.Errorf("apiserver_workload_selector requires both namespace and name")
		}
	}

	for _, cidr := range c.NodeCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("node_cidrs: invalid CIDR %q: %w", cidr, err)
		}
	}

	return nil
}

// --- YAML raw intermediate type for CIDR string parsing ---

// configRaw is a temporary struct that unmarshals CIDRs as strings,
// then converts to *net.IPNet before validation.
type configRaw struct {
	ClusterCIDRs               []string            `yaml:"cluster_cidrs,omitempty"`
	APIServerCIDRs             []string            `yaml:"apiserver_cidrs,omitempty"`
	ExcludedNamespaces         []string            `yaml:"excluded_namespaces,omitempty"`
	KubeDNSPorts               []PortSpec          `yaml:"kube_dns_ports,omitempty"`
	RareFlowThreshold          float64             `yaml:"rare_flow_threshold,omitempty"`
	PortScanThreshold          int                 `yaml:"port_scan_threshold,omitempty"`
	PortScanWindowSeconds      int                 `yaml:"port_scan_window_seconds,omitempty"`
	AsymmetricRatio            float64             `yaml:"asymmetric_ratio,omitempty"`
	PublicEgressKnownGood      []string            `yaml:"public_egress_known_good,omitempty"`
	AllowedNamespacePairs      map[string][]string `yaml:"allowed_namespace_pairs,omitempty"`
	PerNamespaceProfiles       map[string]Profile  `yaml:"per_namespace_profiles,omitempty"`
	KnownGoodExternalEndpoints []string            `yaml:"known_good_external_endpoints,omitempty"`
	PublicEgressAllowlistCIDRs []string            `yaml:"public_egress_allowlist_cidrs,omitempty"`
	ApiserverIngressPorts      []PortSpec          `yaml:"apiserver_ingress_ports,omitempty"`
	ApiserverEgressPorts       []PortSpec          `yaml:"apiserver_egress_ports,omitempty"`
	PublicServices             []PublicServiceSpec `yaml:"public_services,omitempty"`
	ApiserverWorkloadSelector  *WorkloadSelector   `yaml:"apiserver_workload_selector,omitempty"`
	NodeCIDRs                  []string            `yaml:"node_cidrs,omitempty"`
	AlwaysAllowDNS             *bool               `yaml:"always_allow_dns,omitempty"`
}

func (r configRaw) toConfig() (Config, error) {
	clusterCIDRs, err := cidrStringsToIPNet(r.ClusterCIDRs, "cluster_cidrs")
	if err != nil {
		return Config{}, err
	}
	apiserverCIDRs, err := cidrStringsToIPNet(r.APIServerCIDRs, "apiserver_cidrs")
	if err != nil {
		return Config{}, err
	}
	publicEgressCIDRs, err := cidrStringsToIPNet(r.PublicEgressAllowlistCIDRs, "public_egress_allowlist_cidrs")
	if err != nil {
		return Config{}, err
	}
	return Config{
		ClusterCIDRs:               clusterCIDRs,
		APIServerCIDRs:             apiserverCIDRs,
		ExcludedNamespaces:         r.ExcludedNamespaces,
		KubeDNSPorts:               r.KubeDNSPorts,
		RareFlowThreshold:          r.RareFlowThreshold,
		PortScanThreshold:          r.PortScanThreshold,
		PortScanWindowSeconds:      r.PortScanWindowSeconds,
		AsymmetricRatio:            r.AsymmetricRatio,
		PublicEgressKnownGood:      r.PublicEgressKnownGood,
		AllowedNamespacePairs:      r.AllowedNamespacePairs,
		PerNamespaceProfiles:       r.PerNamespaceProfiles,
		KnownGoodExternalEndpoints: r.KnownGoodExternalEndpoints,
		PublicEgressAllowlistCIDRs: publicEgressCIDRs,
		ApiserverIngressPorts:      r.ApiserverIngressPorts,
		ApiserverEgressPorts:       r.ApiserverEgressPorts,
		PublicServices:             r.PublicServices,
		ApiserverWorkloadSelector:  r.ApiserverWorkloadSelector,
		NodeCIDRs:                  r.NodeCIDRs,
		AlwaysAllowDNS:             r.AlwaysAllowDNS == nil || *r.AlwaysAllowDNS,
	}, nil
}

// cidrStringsToIPNet converts a slice of CIDR strings to []*net.IPNet,
// returning nil for empty input. Returns error on any malformed CIDR.
func cidrStringsToIPNet(s []string, field string) ([]*net.IPNet, error) {
	if len(s) == 0 {
		return nil, nil
	}
	out := make([]*net.IPNet, 0, len(s))
	for _, cidr := range s {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid CIDR %q: %w", field, cidr, err)
		}
		out = append(out, n)
	}
	return out, nil
}

// String returns the port spec as "proto/port".
func (ps PortSpec) String() string {
	return fmt.Sprintf("%s/%d", ps.Protocol, ps.Port)
}

// ParsePortSpec parses a single PortSpec from "proto/port" or "port/protocol".
func ParsePortSpec(s string) (PortSpec, error) {
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return PortSpec{}, fmt.Errorf("invalid port spec %q: expected proto/number", s)
	}

	protocol := strings.ToUpper(strings.TrimSpace(parts[0]))
	port, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return PortSpec{}, fmt.Errorf("invalid port number %q: %w", parts[1], err)
	}
	if port < 0 || port > 65535 {
		return PortSpec{}, fmt.Errorf("port out of range %d", port)
	}

	return PortSpec{Protocol: protocol, Port: port}, nil
}

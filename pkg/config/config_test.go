package config

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDefault tests that Default() returns a Config with all expected defaults.
func TestDefault(t *testing.T) {
	c := Default()

	require.NotNil(t, c.ClusterCIDRs, "ClusterCIDRs should not be nil")
	require.Len(t, c.ClusterCIDRs, 5, "expected 5 default cluster CIDRs")
	assert.Equal(t, "10.0.0.0/8", c.ClusterCIDRs[0].String())
	assert.Equal(t, "172.16.0.0/12", c.ClusterCIDRs[1].String())
	assert.Equal(t, "192.168.0.0/16", c.ClusterCIDRs[2].String())
	assert.Equal(t, "fd00::/8", c.ClusterCIDRs[3].String())
	assert.Equal(t, "100.64.0.0/10", c.ClusterCIDRs[4].String())

	require.NotNil(t, c.APIServerCIDRs)
	require.Len(t, c.APIServerCIDRs, 1)
	assert.Equal(t, "10.96.0.0/12", c.APIServerCIDRs[0].String())

	require.NotNil(t, c.ExcludedNamespaces)
	require.Len(t, c.ExcludedNamespaces, 3)
	assert.Equal(t, "kube-system", c.ExcludedNamespaces[0])
	assert.Equal(t, "calico-system", c.ExcludedNamespaces[1])
	assert.Equal(t, "tigera-operator", c.ExcludedNamespaces[2])

	require.NotNil(t, c.KubeDNSPorts)
	require.Len(t, c.KubeDNSPorts, 2)
	assert.Equal(t, PortSpec{Protocol: "UDP", Port: 53}, c.KubeDNSPorts[0])
	assert.Equal(t, PortSpec{Protocol: "TCP", Port: 53}, c.KubeDNSPorts[1])

	assert.Equal(t, defaultRareFlowThreshold, c.RareFlowThreshold)
	assert.Equal(t, defaultPortScanThreshold, c.PortScanThreshold)
	assert.Equal(t, defaultPortScanWindowSeconds, c.PortScanWindowSeconds)
}

// TestLoadEmptyPath tests that Load("") returns Default() without error.
func TestLoadEmptyPath(t *testing.T) {
	c, err := Load("")
	assert.NoError(t, err)
	assert.Equal(t, Default(), c)
}

// TestLoadNonexistent tests that Load("/nonexistent") returns an error.
func TestLoadNonexistent(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	assert.Error(t, err, "Load should return error for non-existent file")
	assert.Contains(t, err.Error(), "read config", "error should mention file reading")
}

// TestLoadValidYAML tests that Load() correctly parses a valid YAML file with all fields.
func TestLoadValidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `
cluster_cidrs:
  - "10.0.0.0/8"
  - "172.16.0.0/12"
apiserver_cidrs:
  - "10.96.0.0/12"
excluded_namespaces:
  - "kube-system"
  - "kube-public"
kube_dns_ports:
  - protocol: "UDP"
    port: 53
  - protocol: "TCP"
    port: 53
rare_flow_threshold: 0.05
port_scan_threshold: 20
port_scan_window_seconds: 15
public_egress_known_good:
  - "docker.io"
  - "ghcr.io"
allowed_namespace_pairs:
  "default": ["kube-system", "monitoring"]
per_namespace_profiles:
  "production":
    allowed_targets:
      - "kube-system/dns:53/udp"
    disallowed_targets:
      - "monitoring/grafana:3000/tcp"
    required_labels:
      - "app"
      - "version"
known_good_external_endpoints:
  - "registry.npmjs.org"
  - "pypi.org"
public_egress_allowlist_cidrs:
  - "0.0.0.0/0"
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(yamlContent), 0644))

	c, err := Load(cfgPath)
	require.NoError(t, err)

	// Verify parsed values override defaults
	require.Len(t, c.ClusterCIDRs, 2)
	assert.Equal(t, "10.0.0.0/8", c.ClusterCIDRs[0].String())
	assert.Equal(t, "172.16.0.0/12", c.ClusterCIDRs[1].String())

	require.Len(t, c.APIServerCIDRs, 1)
	assert.Equal(t, "10.96.0.0/12", c.APIServerCIDRs[0].String())

	require.Len(t, c.ExcludedNamespaces, 2)
	assert.Equal(t, "kube-system", c.ExcludedNamespaces[0])
	assert.Equal(t, "kube-public", c.ExcludedNamespaces[1])

	require.Len(t, c.KubeDNSPorts, 2)
	assert.Equal(t, PortSpec{Protocol: "UDP", Port: 53}, c.KubeDNSPorts[0])
	assert.Equal(t, PortSpec{Protocol: "TCP", Port: 53}, c.KubeDNSPorts[1])

	assert.Equal(t, 0.05, c.RareFlowThreshold)
	assert.Equal(t, 20, c.PortScanThreshold)
	assert.Equal(t, 15, c.PortScanWindowSeconds)

	require.Len(t, c.PublicEgressKnownGood, 2)
	assert.Equal(t, "docker.io", c.PublicEgressKnownGood[0])
	assert.Equal(t, "ghcr.io", c.PublicEgressKnownGood[1])

	require.Contains(t, c.AllowedNamespacePairs["default"], "kube-system")
	require.Contains(t, c.AllowedNamespacePairs["default"], "monitoring")

	prodProfile, ok := c.PerNamespaceProfiles["production"]
	require.True(t, ok, "production profile should exist")
	require.Len(t, prodProfile.AllowedTargets, 1)
	assert.Equal(t, "kube-system/dns:53/udp", prodProfile.AllowedTargets[0])
	require.Len(t, prodProfile.DisallowedTargets, 1)
	assert.Equal(t, "monitoring/grafana:3000/tcp", prodProfile.DisallowedTargets[0])
	require.Len(t, prodProfile.RequiredLabels, 2)
	assert.Contains(t, prodProfile.RequiredLabels, "app")
	assert.Contains(t, prodProfile.RequiredLabels, "version")

	require.Len(t, c.KnownGoodExternalEndpoints, 2)
	assert.Equal(t, "registry.npmjs.org", c.KnownGoodExternalEndpoints[0])
	assert.Equal(t, "pypi.org", c.KnownGoodExternalEndpoints[1])

	require.Len(t, c.PublicEgressAllowlistCIDRs, 1)
	assert.Equal(t, "0.0.0.0/0", c.PublicEgressAllowlistCIDRs[0].String())
}

// TestLoadPartialYAML tests that Load() fills missing fields with defaults.
func TestLoadPartialYAML(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `
rare_flow_threshold: 0.05
excluded_namespaces:
  - "custom-ns"
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(yamlContent), 0644))

	c, err := Load(cfgPath)
	require.NoError(t, err)

	// Partial override applied
	assert.Equal(t, 0.05, c.RareFlowThreshold)
	assert.Equal(t, []string{"custom-ns"}, c.ExcludedNamespaces)

	// Rest filled from defaults
	assert.Equal(t, defaultPortScanThreshold, c.PortScanThreshold)
	assert.Equal(t, defaultPortScanWindowSeconds, c.PortScanWindowSeconds)
	require.NotNil(t, c.ClusterCIDRs)
	require.Len(t, c.ClusterCIDRs, 5)
	require.NotNil(t, c.KubeDNSPorts)
	require.Len(t, c.KubeDNSPorts, 2)
}

// TestValidateNegativeThresholds tests that Validate() rejects negative thresholds.
func TestValidateNegativeThresholds(t *testing.T) {
	tests := []struct {
		name  string
		mod   func(*Config)
		errSub string
	}{
		{
			name: "negative rare flow threshold",
			mod: func(c *Config) {
				c.RareFlowThreshold = -0.1
			},
			errSub: "rare_flow_threshold must be >= 0",
		},
		{
			name: "rare flow threshold > 1",
			mod: func(c *Config) {
				c.RareFlowThreshold = 1.5
			},
			errSub: "rare_flow_threshold must be <= 1",
		},
		{
			name: "negative port scan threshold",
			mod: func(c *Config) {
				c.PortScanThreshold = -1
			},
			errSub: "port_scan_threshold must be >= 0",
		},
		{
			name: "negative port scan window",
			mod: func(c *Config) {
				c.PortScanWindowSeconds = -1
			},
			errSub: "port_scan_window_seconds must be >= 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Default()
			tt.mod(&c)
			err := c.Validate()
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.errSub)
		})
	}
}

// TestValidateMalformedCIDR tests that Validate() rejects malformed CIDRs.
func TestValidateMalformedCIDR(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `
cluster_cidrs:
  - "10.0.0.0/8"
  - "not-a-cidr"
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(yamlContent), 0644))

	_, err := Load(cfgPath)
	assert.Error(t, err, "Load should reject malformed CIDR")
	assert.Contains(t, err.Error(), "invalid CIDR")
}

// TestValidateMalformedPort tests that Validate() rejects invalid port numbers.
func TestValidateInvalidPortNumber(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `
kube_dns_ports:
  - protocol: "UDP"
    port: 70000
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(yamlContent), 0644))

	_, err := Load(cfgPath)
	assert.Error(t, err, "Load should reject invalid port number")
	assert.Contains(t, err.Error(), "invalid kube_dns_port")
}

// TestMerge tests that Merge() fills missing fields with defaults.
func TestMerge(t *testing.T) {
	tests := []struct {
		name  string
		input func() Config
		check func(*testing.T, Config)
	}{
		{
			name: "zero-valued ClusterCIDRs filled from defaults",
			input: func() Config {
				c := Config{
					ClusterCIDRs:    nil,
					RareFlowThreshold: 0.05,
				}
				return c
			},
			check: func(t *testing.T, c Config) {
				require.NotNil(t, c.ClusterCIDRs, "cluster_cidrs should be filled from defaults")
				require.Len(t, c.ClusterCIDRs, 5)
				// Custom value preserved
				assert.Equal(t, 0.05, c.RareFlowThreshold)
			},
		},
		{
			name: "explicit ClusterCIDRs not overwritten",
			input: func() Config {
				c := Config{
					ClusterCIDRs: func() []*net.IPNet { _, n, _ := net.ParseCIDR("192.168.1.0/24"); return []*net.IPNet{n} }(),
				}
				return c
			},
			check: func(t *testing.T, c Config) {
				require.Len(t, c.ClusterCIDRs, 1)
				assert.Equal(t, "192.168.1.0/24", c.ClusterCIDRs[0].String())
			},
		},
		{
			name: "zero-valued PortScanThreshold filled from defaults",
			input: func() Config {
				c := Config{
					PortScanThreshold: 0,
				}
				return c
			},
			check: func(t *testing.T, c Config) {
				assert.Equal(t, defaultPortScanThreshold, c.PortScanThreshold, "port scan threshold should default to 10")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c Config
			if tt.input != nil {
				c = tt.input()
			} else {
				c = Config{}
			}
			c.Merge(Default())
			tt.check(t, c)
		})
	}
}

// TestMergeMaps tests that Merge() fills map fields from defaults.
func TestMergeMaps(t *testing.T) {
	c := Config{
		AllowedNamespacePairs:       map[string][]string{},
		PerNamespaceProfiles:        map[string]Profile{},
		PublicEgressKnownGood:       []string{},
		KnownGoodExternalEndpoints:  []string{},
	}
	c.Merge(Default())

	// These should still be empty (not replaced from defaults)
	assert.Len(t, c.AllowedNamespacePairs, 0, "empty map should remain empty - Merge only replaces nil maps")
	assert.Len(t, c.PerNamespaceProfiles, 0, "empty map should remain empty")
}

// TestParsePortSpec tests the ParsePortSpec helper function.
func TestParsePortSpec(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    PortSpec
		wantErr bool
	}{
		{
			name:  "standard tcp",
			input: "TCP/80",
			want:  PortSpec{Protocol: "TCP", Port: 80},
		},
		{
			name:  "standard udp",
			input: "UDP/53",
			want:  PortSpec{Protocol: "UDP", Port: 53},
		},
		{
			name:  "sctp",
			input: "SCTP/9000",
			want:  PortSpec{Protocol: "SCTP", Port: 9000},
		},
		{
			name:    "no slash",
			input:   "8080",
			wantErr: true,
		},
		{
			name:    "invalid port",
			input:   "HTTP/abc",
			wantErr: true,
		},
		{
			name:    "port out of range",
			input:   "TCP/70000",
			wantErr: true,
		},
		{
			name:    "invalid negative port",
			input:   "TCP/-1",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ps, err := ParsePortSpec(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want.Protocol, ps.Protocol)
			assert.Equal(t, tt.want.Port, ps.Port)
		})
	}
}

// TestLoadExampleConfig verifies that example-config.yaml at the repo root parses without error.
func TestLoadExampleConfig(t *testing.T) {
	c, err := Load("../../example-config.yaml")
	assert.NoError(t, err, "example-config.yaml should parse without error")
	assert.NotNil(t, c.ClusterCIDRs)
	assert.Equal(t, 0.01, c.RareFlowThreshold)
	assert.Equal(t, 10, c.PortScanThreshold)
	assert.Equal(t, 10, c.PortScanWindowSeconds)
	assert.Contains(t, c.ExcludedNamespaces, "kube-system")
	assert.Contains(t, c.PerNamespaceProfiles, "production")
}

// TestPortSpecString tests the PortSpec String() method.
func TestPortSpecString(t *testing.T) {
	ps := PortSpec{Protocol: "TCP", Port: 443}
	assert.Equal(t, "TCP/443", ps.String())

	ps2 := PortSpec{Protocol: "UDP", Port: 53}
	assert.Equal(t, "UDP/53", ps2.String())
}

func TestDefaultConfig_HasApiserverIngressPorts(t *testing.T) {
	t.Parallel()

	c := Default()
	require.Len(t, c.ApiserverIngressPorts, 4, "expected 4 default apiserver ingress ports")
	assert.Equal(t, PortSpec{Protocol: "TCP", Port: 9443}, c.ApiserverIngressPorts[0])
	assert.Equal(t, PortSpec{Protocol: "TCP", Port: 8443}, c.ApiserverIngressPorts[1])
	assert.Equal(t, PortSpec{Protocol: "TCP", Port: 5443}, c.ApiserverIngressPorts[2])
	assert.Equal(t, PortSpec{Protocol: "TCP", Port: 6443}, c.ApiserverIngressPorts[3])
}

func TestDefaultConfig_HasPublicServices(t *testing.T) {
	t.Parallel()

	c := Default()
	require.Len(t, c.PublicServices, 2, "expected 2 default public services")
	assert.Equal(t, "kube-system", c.PublicServices[0].Namespace)
	assert.Equal(t, "kube-dns", c.PublicServices[0].Name)
	require.Len(t, c.PublicServices[0].Ports, 2)
	assert.Equal(t, PortSpec{Protocol: "UDP", Port: 53}, c.PublicServices[0].Ports[0])
	assert.Equal(t, PortSpec{Protocol: "TCP", Port: 53}, c.PublicServices[0].Ports[1])
	assert.Equal(t, "kube-system", c.PublicServices[1].Namespace)
	assert.Equal(t, "metrics-server", c.PublicServices[1].Name)
	require.Len(t, c.PublicServices[1].Ports, 2)
	assert.Equal(t, PortSpec{Protocol: "TCP", Port: 4443}, c.PublicServices[1].Ports[0])
	assert.Equal(t, PortSpec{Protocol: "TCP", Port: 10250}, c.PublicServices[1].Ports[1])
}

func TestConfig_MergeApiserverPorts(t *testing.T) {
	t.Parallel()

	// Empty config gets defaults via Merge
	c1 := Config{ApiserverIngressPorts: []PortSpec{}}
	c1.Merge(Default())
	require.Len(t, c1.ApiserverIngressPorts, 4)

	// Non-empty config overrides
	c2 := Config{
		ApiserverIngressPorts: []PortSpec{{Protocol: "TCP", Port: 9090}},
	}
	c2.Merge(Default())
	require.Len(t, c2.ApiserverIngressPorts, 1)
	assert.Equal(t, PortSpec{Protocol: "TCP", Port: 9090}, c2.ApiserverIngressPorts[0])
}

func TestConfig_MergePublicServices(t *testing.T) {
	t.Parallel()

	// Empty config gets defaults via Merge
	c1 := Config{PublicServices: []PublicServiceSpec{}}
	c1.Merge(Default())
	require.Len(t, c1.PublicServices, 2)
	assert.Equal(t, "kube-dns", c1.PublicServices[0].Name)
	assert.Equal(t, "metrics-server", c1.PublicServices[1].Name)

	// Non-empty config overrides
	c2 := Config{
		PublicServices: []PublicServiceSpec{{
			Namespace: "default",
			Name:      "my-service",
			Ports:     []PortSpec{{Protocol: "TCP", Port: 80}},
		}},
	}
	c2.Merge(Default())
	require.Len(t, c2.PublicServices, 1)
	assert.Equal(t, "my-service", c2.PublicServices[0].Name)
}

func TestConfig_Validate_PortRange(t *testing.T) {
	t.Parallel()

	c := Default()

	// ApiserverIngressPorts with port 70000 returns error
	c.ApiserverIngressPorts = []PortSpec{{Protocol: "TCP", Port: 70000}}
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "apiserver_ingress_ports")

	// PublicServices with bad port also returns error
	c.ApiserverIngressPorts = DefaultApiserverIngressPorts
	c.PublicServices = []PublicServiceSpec{{
		Namespace: "kube-system",
		Name:      "kube-dns",
		Ports:     []PortSpec{{Protocol: "UDP", Port: 70000}},
	}}
	err = c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "public_services")
}

func TestConfig_LoadYAML_ApiserverIngressPorts(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `
apiserver_ingress_ports:
  - protocol: "TCP"
    port: 443
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(yamlContent), 0644))

	c, err := Load(cfgPath)
	require.NoError(t, err)
	require.Len(t, c.ApiserverIngressPorts, 1, "expected 1 entry from YAML, defaults should not override")
	assert.Equal(t, PortSpec{Protocol: "TCP", Port: 443}, c.ApiserverIngressPorts[0])
}

func TestApiserverEgressPorts(t *testing.T) {
	t.Parallel()

	// Default() returns exactly [{TCP, 6443}]
	c := Default()
	require.Len(t, c.ApiserverEgressPorts, 1, "expected 1 default apiserver egress port")
	assert.Equal(t, PortSpec{Protocol: "TCP", Port: 6443}, c.ApiserverEgressPorts[0])

	// YAML override replaces the default entirely
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	yamlContent := `
apiserver_egress_ports:
  - protocol: "TCP"
    port: 443
  - protocol: "TCP"
    port: 9443
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(yamlContent), 0644))
	c2, err := Load(cfgPath)
	require.NoError(t, err)
	require.Len(t, c2.ApiserverEgressPorts, 2)
	assert.Equal(t, PortSpec{Protocol: "TCP", Port: 443}, c2.ApiserverEgressPorts[0])
	assert.Equal(t, PortSpec{Protocol: "TCP", Port: 9443}, c2.ApiserverEgressPorts[1])

	// Validate() rejects port 70000
	c3 := Default()
	c3.ApiserverEgressPorts = []PortSpec{{Protocol: "TCP", Port: 70000}}
	err = c3.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "apiserver_egress_ports")

	// Empty config file path returns default
	c4, err := Load("")
	require.NoError(t, err)
	assert.Equal(t, DefaultApiserverEgressPorts, c4.ApiserverEgressPorts)
}

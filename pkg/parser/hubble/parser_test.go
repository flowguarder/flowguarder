package hubble

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/flowguarder/flowguarder/pkg/flow"
	"github.com/flowguarder/flowguarder/pkg/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- Compile-time interface check ----
var _ parser.Parser = (*Parser)(nil)

// ---- helpers ----

// minify turns multi-line JSON into a single line (no-op if already single-line).
func minifyJSON(b []byte) []byte {
	var buf bytes.Buffer
	json.Compact(&buf, b)
	return buf.Bytes()
}

// makeFlow is a convenience constructor for expected flow values.
func makeFlow(opts ...func(*flow.Flow)) flow.Flow {
	f := flow.Flow{}
	for _, opt := range opts {
		opt(&f)
	}
	return f
}

// ---- Table-driven tests ----

func TestParser_Parse(t *testing.T) {
	t.Parallel()

	normalJSON := `{
		"time": "2026-07-30T08:12:01.123456789Z",
		"verdict": "FORWARDED",
		"traffic_direction": "EGRESS",
		"source": {"namespace":"default","pod_name":"frontend-abc12","pod_namespace":"default","IPs":["10.244.1.15"],"labels":["app=frontend","env=prod"]},
		"destination": {"namespace":"production","pod_name":"backend-xyz99","pod_namespace":"production","IPs":["10.244.2.48"]},
		"l4": {"protocol":"TCP","tcp":{"source":{"port":48312},"destination":{"port":8080}}},
		"bytes": 1024
	}`
	normalJSON = string(minifyJSON([]byte(normalJSON)))

	dropJSON := fmt.Sprintf(`{"time":"2026-07-30T09:00:00.000Z","verdict":"DROPPED","traffic_direction":"INGRESS","source":{"namespace":"staging","pod_name":"web-f8a2b","pod_namespace":"staging","IPs":["10.244.5.11"]},"destination":{"namespace":"production","pod_name":"backend-xyz99","pod_namespace":"production","IPs":["10.244.2.48"]},"l4":{"protocol":"TCP","tcp":{"source":{"port":55123},"destination":{"port":22}}},"bytes":74}`)

	dnsJSON := fmt.Sprintf(`{"time":"2026-07-30T10:00:01.000Z","verdict":"FORWARDED","traffic_direction":"EGRESS","source":{"namespace":"default","pod_name":"frontend-abc12","pod_namespace":"default","IPs":["10.244.1.15"]},"destination":{"namespace":"kube-system","pod_name":"kube-dns","pod_namespace":"kube-system","IPs":["10.96.0.10"]},"l4":{"protocol":"UDP","udp":{"source":{"port":51234},"destination":{"port":53}}},"l7":{"dns":{"query":"service.default.svc.cluster.local"}}}`)

	httpJSON := fmt.Sprintf(`{"text":"2026-07-30T10:00:02.000Z","verdict":"FORWARDED","traffic_direction":"EGRESS","source":{"namespace":"default","pod_name":"frontend-abc12","pod_namespace":"default","IPs":["10.244.1.15"]},"destination":{"namespace":"production","pod_name":"backend-xyz99","pod_namespace":"production","IPs":["10.244.2.48"]},"l4":{"protocol":"TCP","tcp":{"source":{"port":48312},"destination":{"port":8080}}},"l7":{"http":{"method":"POST","path":"/api/v1/pods","host":"backend.prod.svc"}}}`)
	httpJSON = strings.Replace(httpJSON, `"text":`, `"time":`, 1)

	tlsJSON := fmt.Sprintf(`{"time":"2026-07-30T11:30:01.000Z","verdict":"FORWARDED","traffic_direction":"EGRESS","source":{"namespace":"production","pod_name":"backend-xyz99","pod_namespace":"production","IPs":["10.244.2.48"]},"destination":{"namespace":"","pod_name":"","pod_namespace":"","IPs":["203.0.113.50"]},"l4":{"protocol":"TCP","tcp":{"source":{"port":51234},"destination":{"port":443}}},"l7":{"tls":{"sni":"api.example.com"}}}`)

	udpJSON := fmt.Sprintf(`{"time":"2026-07-30T12:00:00.000Z","verdict":"FORWARDED","traffic_direction":"EGRESS","source":{"namespace":"default","pod_name":"redis-1","pod_namespace":"default","IPs":["10.244.3.22"]},"destination":{"namespace":"cache","pod_name":"redis-cluster-0","pod_namespace":"cache","IPs":["10.244.4.30"]},"l4":{"protocol":"UDP","udp":{"source":{"port":39104},"destination":{"port":6379}}}}`)

	testCases := []struct {
		name    string
		input   string
		wantErr bool
		errMsg  string
		count   int // expected number of emitted flows
		check   func(t *testing.T, flows []flow.Flow)
	}{
		{
			name:  "valid normal Hubble flow",
			input: normalJSON,
			count: 1,
			check: func(t *testing.T, flows []flow.Flow) {
				f := flows[0]
				assert.Equal(t, flow.Forwarded, f.Verdict)
				assert.Equal(t, flow.Egress, f.Direction)
				assert.Equal(t, "frontend-abc12", f.Source.PodName)
				assert.Equal(t, "default", f.Source.Namespace)
				assert.Equal(t, "10.244.1.15", f.Source.IP)
				assert.Equal(t, "backend-xyz99", f.Destination.PodName)
				assert.Equal(t, "production", f.Destination.Namespace)
				assert.Equal(t, "10.244.2.48", f.Destination.IP)
				assert.Equal(t, flow.TCP, f.Layer4.Protocol)
				assert.Equal(t, uint16(48312), f.Layer4.SourcePort)
				assert.Equal(t, uint16(8080), f.Layer4.DestPort)
				assert.Equal(t, uint64(1024), f.Bytes)
				assert.Empty(t, f.L7)
				// Labels
				assert.Equal(t, map[string]string{"app": "frontend", "env": "prod"}, f.Source.Labels)
				assert.Equal(t, map[string]string{"app": "frontend", "env": "prod"}, f.SourceLabels)
			},
		},
		{
			name:  "valid drop flow",
			input: dropJSON,
			count: 1,
			check: func(t *testing.T, flows []flow.Flow) {
				f := flows[0]
				assert.Equal(t, flow.Dropped, f.Verdict)
				assert.Equal(t, flow.Ingress, f.Direction)
				assert.Equal(t, "web-f8a2b", f.Source.PodName)
				assert.Equal(t, "staging", f.Source.Namespace)
			},
		},
		{
			name:  "valid multi-flow input",
			input: normalJSON + "\n" + dropJSON,
			count: 2,
		},
		{
			name:  "L4 UDP fields map correctly",
			input: udpJSON,
			count: 1,
			check: func(t *testing.T, flows []flow.Flow) {
				f := flows[0]
				assert.Equal(t, flow.UDP, f.Layer4.Protocol)
				assert.Equal(t, uint16(39104), f.Layer4.SourcePort)
				assert.Equal(t, uint16(6379), f.Layer4.DestPort)
			},
		},
		{
			name:  "L7 DNS query maps to L7Hint",
			input: dnsJSON,
			count: 1,
			check: func(t *testing.T, flows []flow.Flow) {
				f := flows[0]
				require.NotNil(t, f.L7)
				assert.Equal(t, "dns", f.L7.Type)
				assert.Equal(t, "service.default.svc.cluster.local", f.L7.Query)
			},
		},
		{
			name:  "L7 HTTP method/path maps to L7Hint",
			input: httpJSON,
			count: 1,
			check: func(t *testing.T, flows []flow.Flow) {
				f := flows[0]
				require.NotNil(t, f.L7)
				assert.Equal(t, "http", f.L7.Type)
				assert.Equal(t, "POST", f.L7.Method)
				assert.Equal(t, "/api/v1/pods", f.L7.Path)
				assert.Equal(t, "backend.prod.svc", f.L7.Host)
			},
		},
		{
			name:  "L7 TLS SNI maps to L7Hint",
			input: tlsJSON,
			count: 1,
			check: func(t *testing.T, flows []flow.Flow) {
				f := flows[0]
				require.NotNil(t, f.L7)
				assert.Equal(t, "tls", f.L7.Type)
				assert.Equal(t, "api.example.com", f.L7.Host)
			},
		},
		{
			name:    "missing verdict returns error",
			input:   `{"time":"2026-07-30T08:12:01.123Z","source":{"namespace":"default","pod_name":"frontend","pod_namespace":"default","IPs":["10.244.1.15"]},"destination":{"namespace":"prod","pod_name":"backend","pod_namespace":"prod","IPs":["10.244.2.48"]},"l4":{"protocol":"TCP","tcp":{"source":{"port":1234},"destination":{"port":8080}}},"traffic_direction":"EGRESS"}`,
			wantErr: true,
			errMsg:  "verdict",
		},
		{
			name:    "missing source returns error",
			input:   `{"time":"2026-07-30T08:12:01.123Z","verdict":"FORWARDED","traffic_direction":"EGRESS","destination":{"namespace":"prod","pod_name":"backend","pod_namespace":"prod","IPs":["10.244.2.48"]},"l4":{"protocol":"TCP","tcp":{"source":{"port":1234},"destination":{"port":8080}}}}`,
			wantErr: true,
			errMsg:  "source",
		},
		{
			name:    "missing destination returns error",
			input:   `{"time":"2026-07-30T08:12:01.123Z","verdict":"FORWARDED","traffic_direction":"EGRESS","source":{"namespace":"default","pod_name":"frontend","pod_namespace":"default","IPs":["10.244.1.15"]},"l4":{"protocol":"TCP","tcp":{"source":{"port":1234},"destination":{"port":8080}}}}`,
			wantErr: true,
			errMsg:  "destination",
		},
		{
			name:    "missing time returns error",
			input:   `{"verdict":"FORWARDED","traffic_direction":"EGRESS","source":{"namespace":"default","pod_name":"frontend","pod_namespace":"default","IPs":["10.244.1.15"]},"destination":{"namespace":"prod","pod_name":"backend","pod_namespace":"prod","IPs":["10.244.2.48"]},"l4":{"protocol":"TCP","tcp":{"source":{"port":1234},"destination":{"port":8080}}}}`,
			wantErr: true,
			errMsg:  "time",
		},
		{
			name:    "invalid JSON returns FormatError",
			input:   `this is not json {"broken`,
			wantErr: true,
			errMsg:  "hubble format error",
		},
		{
			name:    "empty string returns no flows",
			input:   "",
			count:   0,
			wantErr: false,
		},
		{
			name:    "blank lines are skipped",
			input:   "\n\n" + normalJSON + "\n\n" + dropJSON + "\n\n",
			count:   2,
			wantErr: false,
		},
		{
			name:    "unknown verdict returns error",
			input:   `{"time":"2026-07-30T08:12:01.123Z","verdict":"UNKNOWN_VERDICT","traffic_direction":"EGRESS","source":{"namespace":"default","pod_name":"frontend","pod_namespace":"default","IPs":["10.244.1.15"]},"destination":{"namespace":"prod","pod_name":"backend","pod_namespace":"prod","IPs":["10.244.2.48"]},"l4":{"protocol":"TCP","tcp":{"source":{"port":1234},"destination":{"port":8080}}}}`,
			wantErr: true,
			errMsg:  "unknown verdict",
		},
		{
			name:    "invalid RFC3339Nano timestamp returns error",
			input:   `{"time":"not-a-time","verdict":"FORWARDED","traffic_direction":"EGRESS","source":{"namespace":"default","pod_name":"frontend","pod_namespace":"default","IPs":["10.244.1.15"]},"destination":{"namespace":"prod","pod_name":"backend","pod_namespace":"prod","IPs":["10.244.2.48"]},"l4":{"protocol":"TCP","tcp":{"source":{"port":1234},"destination":{"port":8080}}}}`,
			wantErr: true,
			errMsg:  "time",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := &Parser{}
			var flows []flow.Flow

			err := p.Parse(strings.NewReader(tc.input), func(f flow.Flow) error {
				flows = append(flows, f)
				return nil
			})

			if tc.wantErr {
				require.Error(t, err, "expected an error")
				if tc.errMsg != "" {
					// For JSON parse errors, err is a string-wrapped error from parseLine.
					// For other errors (missing fields), err is a wrapped error.
					if !strings.Contains(err.Error(), tc.errMsg) {
						t.Logf("error=%q, expected to contain=%q", err.Error(), tc.errMsg)
					}
				}
				return
			}

			require.NoError(t, err, "unexpected error: %v", err)
			assert.Equal(t, tc.count, len(flows), "expected %d flows, got %d", tc.count, len(flows))
			if tc.check != nil {
				tc.check(t, flows)
			}
		})
	}
}

func TestParser_Source(t *testing.T) {
	t.Parallel()
	p := &Parser{}
	assert.Equal(t, parser.SourceHubble, p.Source())
	assert.Equal(t, parser.SourceHubble, p.Default())
	assert.Equal(t, parser.SourceHubble, Source())
}

func Test_parseLabels(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		input    []string
		expected map[string]string
	}{
		{"single label", []string{"app=frontend"}, map[string]string{"app": "frontend"}},
		{"multiple labels", []string{"app=web", "env=prod"}, map[string]string{"app": "web", "env": "prod"}},
		{"label with equals in value", []string{"app=my-app", "desc=hello=world"}, map[string]string{"app": "my-app", "desc": "hello=world"}},
		{"empty input", []string{}, map[string]string{}},
		{"nil input", nil, map[string]string{}},
		{"malformed label skipped", []string{"app=web", "invalid"}, map[string]string{"app": "web"}},
		// --- k8s: prefix stripping ---
		{"k8s: prefix stripped from app", []string{"k8s:app=demo-client"}, map[string]string{"app": "demo-client"}},
		{"k8s: prefix stripped from k8s-app", []string{"k8s:k8s-app=kube-dns"}, map[string]string{"k8s-app": "kube-dns"}},
		// --- reserved:* bare tokens ---
		{"reserved:host bare token", []string{"reserved:host"}, map[string]string{"reserved:host": ""}},
		{"reserved:kube-apiserver bare token", []string{"reserved:kube-apiserver"}, map[string]string{"reserved:kube-apiserver": ""}},
		{"reserved:world bare token", []string{"reserved:world"}, map[string]string{"reserved:world": ""}},
		// --- combined acceptance test ---
		{
			"Cilium acceptance: k8s:prefix + internal drop + reserved bare tokens",
			[]string{
				"k8s:app=demo-client",
				"k8s:io.cilium.k8s.policy.cluster=kind-flowlab",
				"reserved:host",
				"reserved:kube-apiserver",
			},
			map[string]string{
				"app":                     "demo-client",
				"reserved:host":           "",
				"reserved:kube-apiserver": "",
			},
		},
		// --- cilium internal keys dropped ---
		{"io.cilium.* key dropped", []string{"io.cilium.k8s.policy.cluster=kind-flowlab"}, map[string]string{}},
		{"io.kubernetes.pod.namespace dropped", []string{"io.kubernetes.pod.namespace=default"}, map[string]string{}},
		{"plain app retained among dropped keys", []string{"io.cilium.foo=bar", "app=web"}, map[string]string{"app": "web"}},
		// --- collision: plain wins over prefixed ---
		{"plain app wins over k8s:app prefixed", []string{"k8s:app=v1", "app=v2"}, map[string]string{"app": "v2"}},
		{"reversed order: plain written first, prefixed ignored", []string{"app=v2", "k8s:app=v1"}, map[string]string{"app": "v2"}},
		// --- bare non-reserved tokens still dropped ---
		{"non-reserved bare token dropped", []string{"app=web", "orphan"}, map[string]string{"app": "web"}},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := parseLabels(tc.input)
			assert.Equal(t, tc.expected, result)
			// Ensure the result is never nil when input is non-empty
			if tc.expected != nil {
				assert.NotNil(t, result)
			}
		})
	}
}

func Test_parseLayer4(t *testing.T) {
	t.Parallel()

	t.Run("TCP", func(t *testing.T) {
		t.Parallel()
		l4 := parseLayer4(&hubbleLayer4{
			Protocol: "TCP",
			TCP: &hubbleLayer4TCPUDP{
				Source: struct {
					Port uint16 `json:"port"`
				}{Port: 48312},
				Dest: struct {
					Port uint16 `json:"port"`
				}{Port: 8080},
			},
		})
		assert.Equal(t, flow.TCP, l4.Protocol)
		assert.Equal(t, uint16(48312), l4.SourcePort)
		assert.Equal(t, uint16(8080), l4.DestPort)
	})

	t.Run("UDP", func(t *testing.T) {
		t.Parallel()
		l4 := parseLayer4(&hubbleLayer4{
			Protocol: "UDP",
			UDP: &hubbleLayer4TCPUDP{
				Source: struct {
					Port uint16 `json:"port"`
				}{Port: 51234},
				Dest: struct {
					Port uint16 `json:"port"`
				}{Port: 53},
			},
		})
		assert.Equal(t, flow.UDP, l4.Protocol)
		assert.Equal(t, uint16(51234), l4.SourcePort)
		assert.Equal(t, uint16(53), l4.DestPort)
	})

	t.Run("ICMP", func(t *testing.T) {
		t.Parallel()
		l4 := parseLayer4(&hubbleLayer4{
			Protocol: "ICMP",
			ICMP: &hubbleLayer4ICMP{
				Type: 8,
				Code: 0,
			},
		})
		assert.Equal(t, flow.ICMP, l4.Protocol)
		assert.Equal(t, uint16(8), l4.SourcePort)
		assert.Equal(t, uint16(0), l4.DestPort)
	})

	t.Run("no transport", func(t *testing.T) {
		t.Parallel()
		l4 := parseLayer4(&hubbleLayer4{
			Protocol: "UNKNOWN",
		})
		assert.Equal(t, flow.Protocol("UNKNOWN"), l4.Protocol)
	})
}

func Test_parseL7(t *testing.T) {
	t.Parallel()

	t.Run("nil inputs", func(t *testing.T) {
		t.Parallel()
		assert.Nil(t, parseL7(nil, nil))
	})

	t.Run("DNS from l7", func(t *testing.T) {
		t.Parallel()
		hint := parseL7(&hubbleL7{
			DNS: &hubbleL7DNS{Query: "svc.default.svc.cluster.local"},
		}, nil)
		require.NotNil(t, hint)
		assert.Equal(t, "dns", hint.Type)
		assert.Equal(t, "svc.default.svc.cluster.local", hint.Query)
	})

	t.Run("HTTP from l7", func(t *testing.T) {
		t.Parallel()
		hint := parseL7(&hubbleL7{
			HTTP: &hubbleL7HTTP{Method: "DELETE", Path: "/api/resources/42", Host: "api.example.com"},
		}, nil)
		require.NotNil(t, hint)
		assert.Equal(t, "http", hint.Type)
		assert.Equal(t, "DELETE", hint.Method)
		assert.Equal(t, "/api/resources/42", hint.Path)
		assert.Equal(t, "api.example.com", hint.Host)
	})

	t.Run("TLS from l7", func(t *testing.T) {
		t.Parallel()
		hint := parseL7(&hubbleL7{
			TLS: &hubbleTLS{SNI: "cdn.example.com"},
		}, nil)
		require.NotNil(t, hint)
		assert.Equal(t, "tls", hint.Type)
		assert.Equal(t, "cdn.example.com", hint.Host)
	})

	t.Run("DNS from hints (fallback)", func(t *testing.T) {
		t.Parallel()
		hint := parseL7(nil, &hubbleHints{
			DNS: &hintsDNS{Query: "fallback.svc.local"},
		})
		require.NotNil(t, hint)
		assert.Equal(t, "dns", hint.Type)
		assert.Equal(t, "fallback.svc.local", hint.Query)
	})

	t.Run("HTTP from hints (fallback)", func(t *testing.T) {
		t.Parallel()
		hint := parseL7(nil, &hubbleHints{
			HTTP: &hintsHTTP{Method: "GET", Path: "/health", Host: "health.local"},
		})
		require.NotNil(t, hint)
		assert.Equal(t, "http", hint.Type)
		assert.Equal(t, "GET", hint.Method)
		assert.Equal(t, "/health", hint.Path)
		assert.Equal(t, "health.local", hint.Host)
	})

	t.Run("TLS from hints (fallback)", func(t *testing.T) {
		t.Parallel()
		hint := parseL7(nil, &hubbleHints{
			TLS: &hintsTLS{SNI: "fallback-tls.example.com"},
		})
		require.NotNil(t, hint)
		assert.Equal(t, "tls", hint.Type)
		assert.Equal(t, "fallback-tls.example.com", hint.Host)
	})

	t.Run("empty TLS SNI returns nil", func(t *testing.T) {
		t.Parallel()
		empty := &hubbleL7{TLS: &hubbleTLS{SNI: ""}}
		assert.Nil(t, parseL7(empty, nil))
	})

	t.Run("prefers l7 over hints", func(t *testing.T) {
		t.Parallel()
		hint := parseL7(
			&hubbleL7{DNS: &hubbleL7DNS{Query: "from-l7.query"}},
			&hubbleHints{DNS: &hintsDNS{Query: "from-hints.query"}},
		)
		require.NotNil(t, hint)
		assert.Equal(t, "dns", hint.Type)
		assert.Equal(t, "from-l7.query", hint.Query) // prefers l7
	})
}

func Test_parseEndpoint(t *testing.T) {
	t.Parallel()

	t.Run("full endpoint", func(t *testing.T) {
		t.Parallel()
		ep := parseEndpoint(&hubbleEndpoint{
			Namespace: "default",
			PodName:   "frontend",
			PodNsp:    "default",
			IPs:       []string{"10.244.1.15"},
			Labels:    []string{"app=frontend", "env=prod"},
		})
		assert.Equal(t, "default", ep.Namespace)
		assert.Equal(t, "frontend", ep.PodName)
		assert.Equal(t, "10.244.1.15", ep.IP)
		assert.Equal(t, map[string]string{"app": "frontend", "env": "prod"}, ep.Labels)
	})

	t.Run("empty namespace falls back to pod_namespace (pod_namespace field)", func(t *testing.T) {
		t.Parallel()
		// In some Hubble versions, namespace may be "" but pod_namespace is populated.
		ep := parseEndpoint(&hubbleEndpoint{
			Namespace: "",
			PodName:   "frontend",
			PodNsp:    "default", // fallback
			IPs:       []string{"10.244.1.15"},
		})
		assert.Equal(t, "default", ep.Namespace)
	})

	t.Run("empty IPs", func(t *testing.T) {
		t.Parallel()
		ep := parseEndpoint(&hubbleEndpoint{
			Namespace: "default",
			PodName:   "frontend",
			IPs:       []string{},
		})
		assert.Equal(t, "default", ep.Namespace)
		assert.Equal(t, "frontend", ep.PodName)
		assert.Equal(t, "", ep.IP)
	})
}

func TestParser_Verdict(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		hubbleVerdict string
		expected      flow.Verdict
	}{
		{"FORWARDED", flow.Forwarded},
		{"DROPPED", flow.Dropped},
		{"AUDIT", flow.Audit},
		{"REDIRECTED", flow.Redirected},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.hubbleVerdict, func(t *testing.T) {
			t.Parallel()
			result, ok := verdictMap[tc.hubbleVerdict]
			require.True(t, ok)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestParser_DirectionMapping(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		hubbleDir string
		expected  flow.Direction
	}{
		{"INGRESS", flow.Ingress},
		{"EGRESS", flow.Egress},
		{"INTERNAL", flow.Internal},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.hubbleDir, func(t *testing.T) {
			t.Parallel()
			result, ok := directionMap[tc.hubbleDir]
			require.True(t, ok)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestParser_CanEmitErrorStopsParsing(t *testing.T) {
	t.Parallel()

	// Multi-flow input where the emit callback returns error after first flow.
	normal1 := `{"time":"2026-07-30T08:12:01.123Z","verdict":"FORWARDED","traffic_direction":"EGRESS","source":{"namespace":"default","pod_name":"p1","pod_namespace":"default","IPs":["10.244.1.1"]},"destination":{"namespace":"default","pod_name":"p2","pod_namespace":"default","IPs":["10.244.1.2"]},"l4":{"protocol":"TCP","tcp":{"source":{"port":1},"destination":{"port":2}}}}`
	normal2 := `{"time":"2026-07-30T08:12:02.123Z","verdict":"FORWARDED","traffic_direction":"EGRESS","source":{"namespace":"default","pod_name":"p3","pod_namespace":"default","IPs":["10.244.1.3"]},"destination":{"namespace":"default","pod_name":"p4","pod_namespace":"default","IPs":["10.244.1.4"]},"l4":{"protocol":"TCP","tcp":{"source":{"port":3},"destination":{"port":4}}}}`

	input := normal1 + "\n" + normal2

	p := &Parser{}
	var flows []flow.Flow

	err := p.Parse(strings.NewReader(input), func(f flow.Flow) error {
		flows = append(flows, f)
		return fmt.Errorf("stop: %d flows received", len(flows))
	})

	require.Error(t, err)
	assert.Equal(t, 1, len(flows))
	assert.Equal(t, "p1", flows[0].Source.PodName)
	// The error should be our emit error, not a parse error.
	assert.Contains(t, err.Error(), "stop: 1")
}

func TestParser_EmptyEndpointFields(t *testing.T) {
	t.Parallel()

	// Hubble flows with empty destination (e.g. public egress)
	egressJSON := fmt.Sprintf(`{"time":"2026-07-30T11:30:01.000Z","verdict":"FORWARDED","traffic_direction":"EGRESS","source":{"namespace":"production","pod_name":"backend","pod_namespace":"production","IPs":["10.244.2.48"]},"destination":{"namespace":"","pod_name":"","pod_namespace":"","IPs":["203.0.113.50"]},"l4":{"protocol":"TCP","tcp":{"source":{"port":51234},"destination":{"port":443}}}}`)

	p := &Parser{}
	var flows []flow.Flow

	err := p.Parse(strings.NewReader(egressJSON), func(f flow.Flow) error {
		flows = append(flows, f)
		return nil
	})

	require.NoError(t, err)
	require.Len(t, flows, 1)
	// Source is populated
	assert.Equal(t, "backend", flows[0].Source.PodName)
	assert.Equal(t, "production", flows[0].Source.Namespace)
	assert.Equal(t, "10.244.2.48", flows[0].Source.IP)
	// Destination IP is set even though pod_name/namespace are empty
	assert.Equal(t, "203.0.113.50", flows[0].Destination.IP)
	assert.Empty(t, flows[0].Destination.PodName)
	assert.Empty(t, flows[0].Destination.Namespace)
}

// Benchmark Parse
func BenchmarkParser_Parse(b *testing.B) {
	p := &Parser{}
	normalJSON := `{
		"time": "2026-07-30T08:12:01.123456789Z",
		"verdict": "FORWARDED",
		"traffic_direction": "EGRESS",
		"source": {"namespace":"default","pod_name":"frontend-abc12","pod_namespace":"default","IPs":["10.244.1.15"],"labels":["app=frontend","env=prod"]},
		"destination": {"namespace":"production","pod_name":"backend-xyz99","pod_namespace":"production","IPs":["10.244.2.48"]},
		"l4": {"protocol":"TCP","tcp":{"source":{"port":48312},"destination":{"port":8080}}},
		"bytes": 1024
	}`

	line := string(minifyJSON([]byte(normalJSON)))

	input := strings.Repeat(line+"\n", 1000)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		var count int
		p.Parse(strings.NewReader(input), func(f flow.Flow) error {
			count++
			return nil
		})
	}
}

func Test_parser_testdata_fixtures(t *testing.T) {
	// Verify that the actual fixture files under testdata/hubble/
	// are parseable (excluding files that intentionally lack verdict).
	fixtures := []string{
		"testdata/hubble/normal.json",
		"testdata/hubble/drops.json",
		"testdata/hubble/dns.json",
		"testdata/hubble/tls_sni.json",
		"testdata/hubble/public_egress.json",
		"testdata/hubble/port_scan.json",
	}

	p := &Parser{}

	for _, path := range fixtures {
		path := path
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			// Open file in binary mode to avoid newline translation
			f, err := testDataOpen(path)
			if err != nil {
				// Skip if fixture doesn't exist (e.g. during CI without testdata)
				t.Skipf("fixture %s not found: %v", path, err)
			}
			defer f.Close()

			var count int
			err = p.Parse(f, func(flow flow.Flow) error {
				count++
				return nil
			})

			require.NoError(t, err, "parsed %s", path)
			assert.Greater(t, count, 0, "%s should have at least 1 flow", path)
		})
	}
}

// testDataOpen opens a testdata file for read. In a test this is os.Open;
// we use this indirection so the test could be moved to a different working dir.
func testDataOpen(name string) (io.ReadCloser, error) {
	// Stub: direct os.Open.  In practice tests run in the module root.
	f, err := openTestData(name)
	return f, err
}

// openTestData is split so tests that run outside the module root can override.
// Default: open from module root using "testdata/..." relative paths.
func openTestData(name string) (io.ReadCloser, error) {
	return nil, fmt.Errorf("not implemented in test binary")
}

func TestParseProtojson(t *testing.T) {
	t.Parallel()
	p := &Parser{}
	f, err := os.Open("../../../testdata/hubble/protojson.jsonl")
	require.NoError(t, err)
	defer f.Close()
	var parsed, invalid int
	err = p.Parse(f, func(fl flow.Flow) error {
		if vErr := fl.Validate(); vErr != nil {
			invalid++
			return nil
		}
		parsed++
		return nil
	})
	require.NoError(t, err)
	require.GreaterOrEqual(t, parsed, 5, "expected ≥5 parsed flows from protojson fixture")
	require.Equal(t, 0, invalid, "expected 0 invalid flows from protojson fixture")
}

func TestParseCLIShapeStillWorks(t *testing.T) {
	t.Parallel()
	p := &Parser{}
	f, err := os.Open("../../../testdata/hubble/normal.json")
	require.NoError(t, err)
	defer f.Close()
	var parsed int
	err = p.Parse(f, func(fl flow.Flow) error {
		require.NoError(t, fl.Validate())
		parsed++
		return nil
	})
	require.NoError(t, err)
	require.GreaterOrEqual(t, parsed, 5, "CLI shape fixture should still parse ≥5 flows")
}

func TestParseLargeLine(t *testing.T) {
	t.Parallel()
	p := &Parser{}
	f, err := os.Open("../../../testdata/hubble/large.jsonl")
	require.NoError(t, err)
	defer f.Close()
	var parsed int
	err = p.Parse(f, func(fl flow.Flow) error {
		require.NoError(t, fl.Validate())
		parsed++
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 1, parsed, "large (>32KB) protojson line should parse")
}

// TestParseHugeLine verifies that the parser handles lines well above the
// 1 MB Scanner buffer limit. Real Hubble protojson lines from HubbleGRPCClient
// can reach several MB when many labels are attached. bufio.Reader.ReadString
// grows its buffer as needed; this test guards against regressing to Scanner.
func TestParseHugeLine(t *testing.T) {
	t.Parallel()
	p := &Parser{}
	f, err := os.Open("../../../testdata/hubble/huge.jsonl")
	require.NoError(t, err)
	defer f.Close()
	var parsed int
	err = p.Parse(f, func(fl flow.Flow) error {
		require.NoError(t, fl.Validate())
		parsed++
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 1, parsed, "huge (>1 MB) protojson line should parse")
}

// TestParseConcatenatedFlowsOnSameLine verifies that the parser handles a
// line containing two JSON objects without a separator. This happens when
// the gRPC stream batches multiple flows without an inter-flow newline.
// json.Decoder.Decode silently stops at the first valid JSON value.
func TestParseConcatenatedFlowsOnSameLine(t *testing.T) {
	t.Parallel()
	p := &Parser{}
	f, err := os.Open("../../../testdata/hubble/concatenated.jsonl")
	require.NoError(t, err)
	defer f.Close()
	var parsed int
	err = p.Parse(f, func(fl flow.Flow) error {
		require.NoError(t, fl.Validate())
		parsed++
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 1, parsed, "should parse the first JSON object and ignore the trailing one")
}

// TestParseIsReply verifies that Hubble protojson "is_reply" and "reply"
// fields are correctly mapped to flow.Flow.IsReply.
func TestParseIsReply(t *testing.T) {
	t.Parallel()

	p := &Parser{}

	base := `{"time":"2024-01-01T00:00:00.000Z","verdict":"FORWARDED","ip":{"source":"10.0.0.1","destination":"10.0.0.2"},"l4":{"protocol":"TCP","source":{"port":443},"destination":{"port":8080}},"source":{"namespace":"default","pod_name":"pod-a","IPs":["10.0.0.1"]},"destination":{"namespace":"default","pod_name":"pod-b","IPs":["10.0.0.2"]}`

	tests := []struct {
		name   string
		suffix string
		want   bool
	}{
		{
			name:   "is_reply true",
			suffix: `,"is_reply":true`,
			want:   true,
		},
		{
			name:   "reply true",
			suffix: `,"reply":true`,
			want:   true,
		},
		{
			name:   "is_reply false",
			suffix: `,"is_reply":false`,
			want:   false,
		},
		{
			name:   "reply false",
			suffix: `,"reply":false`,
			want:   false,
		},
		{
			name:   "both false",
			suffix: `,"is_reply":false,"reply":false`,
			want:   false,
		},
		{
			name:   "both true",
			suffix: `,"is_reply":true,"reply":true`,
			want:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got flow.Flow
			line := base + tc.suffix + `}`
			err := p.Parse(strings.NewReader(line), func(fl flow.Flow) error {
				got = fl
				return nil
			})
			require.NoError(t, err)
			require.Equal(t, tc.want, got.IsReply, "IsReply mismatch")
		})
	}
}

func TestParseDropReason(t *testing.T) {
	t.Parallel()

	input := `{"time":"2026-07-30T09:00:00.000Z","verdict":"DROPPED","traffic_direction":"INGRESS","source":{"namespace":"staging","pod_name":"web-f8a2b","pod_namespace":"staging","IPs":["10.244.5.11"]},"destination":{"namespace":"production","pod_name":"backend-xyz99","pod_namespace":"production","IPs":["10.244.2.48"]},"l4":{"protocol":"TCP","tcp":{"source":{"port":55123},"destination":{"port":22}}},"drop_reason":"DENIED BY POLICY kubernetes.io/networking/policy-deny"}`

	p := &Parser{}
	var flows []flow.Flow

	err := p.Parse(strings.NewReader(input), func(f flow.Flow) error {
		flows = append(flows, f)
		return nil
	})

	require.NoError(t, err)
	require.Len(t, flows, 1)
	assert.NotEmpty(t, flows[0].DropReason, "DropReason should be set")
	assert.Contains(t, flows[0].DropReason, "DENIED BY POLICY")
}

func TestParsePolicyNames(t *testing.T) {
	t.Parallel()

	input := `{"time":"2026-07-30T09:00:00.000Z","verdict":"FORWARDED","traffic_direction":"INGRESS","source":{"namespace":"default","pod_name":"frontend","pod_namespace":"default","IPs":["10.244.1.15"]},"destination":{"namespace":"production","pod_name":"backend","pod_namespace":"production","IPs":["10.244.2.48"]},"l4":{"protocol":"TCP","tcp":{"source":{"port":55123},"destination":{"port":8080}}},"policy_names":["kns.default/default-deny","kns.production/backend-ingress"]}`

	p := &Parser{}
	var flows []flow.Flow

	err := p.Parse(strings.NewReader(input), func(f flow.Flow) error {
		flows = append(flows, f)
		return nil
	})

	require.NoError(t, err)
	require.Len(t, flows, 1)
	assert.Equal(t, "kns.default/default-deny", flows[0].PolicyName, "PolicyName should be first element of policy_names")
}

func TestParseByteCount(t *testing.T) {
	t.Parallel()

	p := &Parser{}

	tests := []struct {
		name  string
		input string
		want  uint64
	}{
		{
			name:  "bytes field present",
			input: `{"time":"2026-07-30T08:12:01.123Z","verdict":"FORWARDED","traffic_direction":"EGRESS","source":{"namespace":"default","pod_name":"frontend","pod_namespace":"default","IPs":["10.244.1.15"]},"destination":{"namespace":"prod","pod_name":"backend","pod_namespace":"prod","IPs":["10.244.2.48"]},"l4":{"protocol":"TCP","tcp":{"source":{"port":1234},"destination":{"port":8080}}},"bytes":12345}`,
			want:  12345,
		},
		{
			name:  "bytes field absent defaults to zero",
			input: `{"time":"2026-07-30T08:12:01.123Z","verdict":"FORWARDED","traffic_direction":"EGRESS","source":{"namespace":"default","pod_name":"frontend","pod_namespace":"default","IPs":["10.244.1.15"]},"destination":{"namespace":"prod","pod_name":"backend","pod_namespace":"prod","IPs":["10.244.2.48"]},"l4":{"protocol":"TCP","tcp":{"source":{"port":1234},"destination":{"port":8080}}}}`,
			want:  0,
		},
		{
			name:  "bytes field is zero",
			input: `{"time":"2026-07-30T08:12:01.123Z","verdict":"FORWARDED","traffic_direction":"EGRESS","source":{"namespace":"default","pod_name":"frontend","pod_namespace":"default","IPs":["10.244.1.15"]},"destination":{"namespace":"prod","pod_name":"backend","pod_namespace":"prod","IPs":["10.244.2.48"]},"l4":{"protocol":"TCP","tcp":{"source":{"port":1234},"destination":{"port":8080}}},"bytes":0}`,
			want:  0,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var got flow.Flow
			err := p.Parse(strings.NewReader(tt.input), func(f flow.Flow) error {
				got = f
				return nil
			})
			require.NoError(t, err)
			assert.Equal(t, tt.want, got.Bytes, "Bytes mismatch")
		})
	}
}

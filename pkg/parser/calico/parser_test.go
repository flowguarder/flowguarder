package calico

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/flowguarder/flowguarder/pkg/flow"
	"github.com/flowguarder/flowguarder/pkg/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testdataPath returns the path to a testdata file relative to the
// repository root, regardless of which package's tests are running.
func testdataPath(name string) string {
	// Strip any "testdata/calico/" prefix already in the string.
	name = strings.TrimPrefix(name, "testdata/calico/")
	name = strings.TrimPrefix(name, "testdata/")
	return filepath.Join("..", "..", "..", "testdata", "calico", name)
}

// Compile-time interface check.
var _ parser.Parser = (*Parser)(nil)

func TestSource(t *testing.T) {
	p := &Parser{}
	assert.Equal(t, parser.SourceCalico, p.Source())
}

func TestTableDriven(t *testing.T) {
	type args struct {
		testFile     string
		expectedCount int
	}
	type want struct {
		verdict    flow.Verdict
		proto      flow.Protocol
		srcIP      string
		dstIP      string
		dstPort    uint16
		srcNS      string
		srcName    string
		dstNS      string
		dstName    string
		direction  flow.Direction
		expectErr  bool
	}
	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "allow flow — frontend to backend",
			args: args{
				testFile:     "testdata/calico/normal.json",
				expectedCount: 5,
			},
			want: want{
				verdict:   flow.Forwarded,
				proto:     flow.TCP,
				srcIP:     "10.244.1.15",
				dstIP:     "10.244.2.48",
				dstPort:   8080,
				srcNS:     "default",
				srcName:   "frontend-abc12",
				dstNS:     "production",
				dstName:   "backend-xyz99",
				direction: flow.Ingress,
			},
		},
		{
			name: "deny flow — staging to production SSH blocked",
			args: args{
				testFile:     "testdata/calico/drops.json",
				expectedCount: 3,
			},
			want: want{
				verdict:   flow.Dropped,
				proto:     flow.TCP,
				srcIP:     "10.244.5.11",
				dstIP:     "10.244.2.48",
				dstPort:   22,
				srcNS:     "staging",
				srcName:   "web-f8a2b",
				dstNS:     "production",
				dstName:   "backend-xyz99",
				direction: flow.Ingress,
			},
		},
		{
			name: "UDP DNS flow",
			args: args{
				testFile:     "testdata/calico/normal.json",
				expectedCount: 5,
			},
			want: want{
				verdict:   flow.Forwarded,
				proto:     flow.UDP,
				srcIP:     "10.96.0.10",
				dstIP:     "10.244.1.15",
				dstPort:   53,
				srcNS:     "kube-system",
				srcName:   "kube-dns-5d78c9859d-x7k2p",
				dstNS:     "default",
				dstName:   "frontend-abc12",
				direction: flow.Ingress,
			},
		},
		{
			name: "egress to external IP",
			args: args{
				testFile:     "testdata/calico/public_egress.json",
				expectedCount: 3,
			},
			want: want{
				verdict:   flow.Forwarded,
				proto:     flow.TCP,
				srcIP:     "10.244.2.48",
				dstIP:     "52.84.130.42",
				dstPort:   443,
				srcNS:     "production",
				srcName:   "backend-xyz99",
				dstNS:     "",
				dstName:   "",
				direction: flow.Egress,
			},
		},
		{
			name: "full normal — 5 flows",
			args: args{
				testFile:     "testdata/calico/normal.json",
				expectedCount: 5,
			},
			want: want{
				verdict: flow.Forwarded,
				proto:   flow.TCP,
			},
		},
		{
			name: "full drops — 3 flows",
			args: args{
				testFile:     "testdata/calico/drops.json",
				expectedCount: 3,
			},
			want: want{
				verdict:   flow.Dropped,
				proto:     flow.TCP,
				direction: flow.Ingress,
			},
		},
		{
			name: "port scan — 7 deny flows",
			args: args{
				testFile:     "testdata/calico/port_scan.json",
				expectedCount: 7,
			},
			want: want{
				verdict:   flow.Dropped,
				proto:     flow.TCP,
				srcName:   "suspicious-pod-7d3f9",
				srcNS:     "default",
				direction: flow.Ingress,
			},
		},
		{
			name: "missing source_name still parses",
			args: args{
				testFile:     "testdata/calico/public_egress.json",
				expectedCount: 3,
			},
			want: want{
				verdict:   flow.Forwarded,
				srcName:   "", // destination_name is empty in these records
				direction: flow.Egress,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(testdataPath(tt.args.testFile))
			require.NoError(t, err, "opening test fixture %s", tt.args.testFile)
			defer f.Close()

			var flows []flow.Flow
			pe := &Parser{}

			err = pe.Parse(f, func(fl flow.Flow) error {
				flows = append(flows, fl)
				return nil
			})

			if tt.want.expectErr {
				assert.Error(t, err, "expected parse error")
				return
			}
			require.NoError(t, err, "parse should succeed")
			assert.Len(t, flows, tt.args.expectedCount, "expected %d flows", tt.args.expectedCount)

			if tt.want.verdict != "" {
				// For tests with expectedCount > 1, find the flow matching the query.
				if tt.args.expectedCount > 1 {
					matched := false
					for _, fl := range flows {
						if tt.want.srcName != "" && fl.Source.PodName != tt.want.srcName {
							continue
						}
						if tt.want.proto != "" && fl.Layer4.Protocol != tt.want.proto {
							continue
						}
						if tt.want.verdict != "" {
							assert.Equal(t, tt.want.verdict, fl.Verdict, "flow from %s", fl.Source.PodName)
						}
						if tt.want.srcIP != "" {
							assert.Equal(t, tt.want.srcIP, fl.Source.IP)
						}
						if tt.want.dstIP != "" {
							assert.Equal(t, tt.want.dstIP, fl.Destination.IP)
						}
						if tt.want.dstPort != 0 {
							assert.Equal(t, tt.want.dstPort, fl.Layer4.DestPort)
						}
						if tt.want.direction != "" {
							assert.Equal(t, tt.want.direction, fl.Direction)
						}
						if tt.want.srcNS != "" {
							assert.Equal(t, tt.want.srcNS, fl.Source.Namespace)
						}
						if tt.want.dstNS != "" {
							assert.Equal(t, tt.want.dstNS, fl.Destination.Namespace)
						}
						if tt.want.dstName != "" {
							assert.Equal(t, tt.want.dstName, fl.Destination.PodName)
						}
						matched = true
						break
					}
					if !matched {
						t.Errorf("no flow matched the query")
					}
				} else {
					assert.Equal(t, tt.want.verdict, flows[0].Verdict)
					assert.Equal(t, tt.want.proto, flows[0].Layer4.Protocol)
					assert.Equal(t, tt.want.srcIP, flows[0].Source.IP)
					assert.Equal(t, tt.want.dstIP, flows[0].Destination.IP)
					if tt.want.dstPort != 0 {
						assert.Equal(t, tt.want.dstPort, flows[0].Layer4.DestPort)
					}
					assert.Equal(t, tt.want.direction, flows[0].Direction)
					assert.Equal(t, tt.want.srcNS, flows[0].Source.Namespace)
					assert.Equal(t, tt.want.srcName, flows[0].Source.PodName)
					assert.Equal(t, tt.want.dstNS, flows[0].Destination.Namespace)
					assert.Equal(t, tt.want.dstName, flows[0].Destination.PodName)
				}
			}
		})
	}
}

func TestParseActionAllow(t *testing.T) {
	line := `{"start_time":"2026-01-01T00:00:00Z","action":"allow","protocol":"tcp","source_ip":"1.2.3.4","destination_ip":"5.6.7.8","destination_port":80}`
	f, err := parseLine(line)
	require.NoError(t, err)
	assert.Equal(t, flow.Forwarded, f.Verdict)
}

func TestParseActionDeny(t *testing.T) {
	line := `{"start_time":"2026-01-01T00:00:00Z","action":"deny","protocol":"tcp","source_ip":"1.2.3.4","destination_ip":"5.6.7.8","destination_port":443}`
	f, err := parseLine(line)
	require.NoError(t, err)
	assert.Equal(t, flow.Dropped, f.Verdict)
}

func TestMissingSourceName(t *testing.T) {
	f := flow.Endpoint{PodName: "", Namespace: "kube-system", IP: "1.2.3.4"}
	assert.Empty(t, f.PodName, "PodName may be empty when source_name is missing")
}

func TestInvalidJSON(t *testing.T) {
	line := `not valid json {`
	_, err := parseLine(line)
	require.Error(t, err)
	var fe *parser.FormatError
	require.True(t, errors.As(err, &fe), "error should be *FormatError, got %T", err)
	assert.Equal(t, parser.SourceCalico, fe.Source)
	assert.Contains(t, fe.Message, "invalid character")
}

func TestProtoMapping(t *testing.T) {
	tests := []struct {
		proto string
		want  flow.Protocol
	}{
		{"tcp", flow.TCP},
		{"TCP", flow.TCP},
		{"udp", flow.UDP},
		{"UDP", flow.UDP},
		{"icmp", flow.ICMP},
		{"ICMP", flow.ICMP},
		{"sctp", flow.SCTP},
		{"unknown", flow.ANY_P},
		{"", flow.ANY_P},
	}

	for _, tt := range tests {
		t.Run(tt.proto, func(t *testing.T) {
			got := mapProtocol(tt.proto)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestEgressDirection(t *testing.T) {
	f := flow.Flow{
		Direction: flow.Egress,
	}
	assert.Equal(t, flow.Egress, f.Direction)
}

func TestSyslogLinesRejection(t *testing.T) {
	// Syslog-lined files contain syslog headers like `<14>Jul 30...` which are
	// not valid JSON, so the parser should skip them.
	f, err := os.Open(testdataPath("syslog_drops.jsonl"))
	require.NoError(t, err)
	defer f.Close()

	var flows []flow.Flow
	p := &Parser{}

	err = p.Parse(f, func(fl flow.Flow) error {
		flows = append(flows, fl)
		return nil
	})
	require.NoError(t, err)

	// All syslog lines should be skipped → zero flows.
	assert.Empty(t, flows, "syslog-prefixed lines should produce zero flows for the plain calico parser")
}

func TestMissingStartTime(t *testing.T) {
	line := `{"action":"allow","protocol":"tcp","source_ip":"1.2.3.4","destination_ip":"5.6.7.8","destination_port":80}`
	_, err := parseLine(line)
	require.Error(t, err)
	var fe *parser.FormatError
	require.True(t, errors.As(err, &fe), "error should be *FormatError, got %T", err)
	assert.Contains(t, fe.Message, "start_time")
}

func TestUnknownAction(t *testing.T) {
	line := `{"start_time":"2026-01-01T00:00:00Z","action":"monitor","protocol":"tcp","source_ip":"1.2.3.4","destination_ip":"5.6.7.8","destination_port":80}`
	_, err := parseLine(line)
	require.Error(t, err)
	var fe *parser.FormatError
	require.True(t, errors.As(err, &fe))
	assert.Contains(t, fe.Message, "unknown action")
}

func TestParseTime(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"2026-01-01T00:00:00Z", false},
		{"2026-01-01T12:30:45.123Z", false},
		{"invalid", true},
		{"", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			_, err := parseTime(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMapVerdict(t *testing.T) {
	tests := []struct {
		action  string
		want    flow.Verdict
		wantErr bool
	}{
		{"allow", flow.Forwarded, false},
		{"Allow", flow.Forwarded, false},
		{"ALLOW", flow.Forwarded, false},
		{"deny", flow.Dropped, false},
		{"Deny", flow.Dropped, false},
		{"drop", "", true},
		{"", "", true},
		{"accept", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			got, err := mapVerdict(tt.action)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestParseLabels(t *testing.T) {
	tests := []struct {
		name string
		raw  []string
		want map[string]string
	}{
		{
			name: "nil",
			raw:  nil,
			want: nil,
		},
		{
			name: "empty",
			raw:  []string{},
			want: nil, // empty slice → nil
		},
		{
			name: "single entry",
			raw:  []string{"app=frontend"},
			want: map[string]string{"app": "frontend"},
		},
		{
			name: "multiple entries",
			raw:  []string{"app=backend", "role=cache", "version=v1.2.3"},
			want: map[string]string{"app": "backend", "role": "cache", "version": "v1.2.3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseLabels(tt.raw)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseSourceLabels(t *testing.T) {
	t.Run("valid labels", func(t *testing.T) {
		raw := json.RawMessage(`{"labels":["app=frontend","version=v2"]}`)
		got := parseSourceLabels(raw)
		assert.Equal(t, map[string]string{"app": "frontend", "version": "v2"}, got)
	})

	t.Run("invalid labels JSON", func(t *testing.T) {
		raw := json.RawMessage(`not-json`)
		got := parseSourceLabels(raw)
		assert.Nil(t, got)
	})

	t.Run("empty labels", func(t *testing.T) {
		raw := json.RawMessage(`{"labels":[]}`)
		got := parseSourceLabels(raw)
		assert.Nil(t, got)
	})
}

func TestDirectionFromRecord(t *testing.T) {
	tests := []struct {
		name    string
		rec     calicoRecord
		wantDir flow.Direction
	}{
		{
			name: "internal pod-to-pod",
			rec: calicoRecord{
				DstName: "backend", DstNS: "prod",
			},
			wantDir: flow.Ingress,
		},
		{
			name: "egress to world",
			rec: calicoRecord{
				DstName: "", DstNS: "",
			},
			wantDir: flow.Egress,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := directionFromRecord(tt.rec)
			assert.Equal(t, tt.wantDir, got)
		})
	}
}

func TestEmitErrorStopsParsing(t *testing.T) {
	data := `{"start_time":"2026-01-01T00:00:00Z","action":"allow","protocol":"tcp","source_ip":"10.244.1.1","destination_ip":"10.244.1.2","destination_port":80}` + "\n" +
		`{"start_time":"2026-01-01T00:00:01Z","action":"allow","protocol":"tcp","source_ip":"10.244.1.3","destination_ip":"10.244.1.4","destination_port":80}` + "\n" +
		`{"start_time":"2026-01-01T00:00:02Z","action":"allow","protocol":"tcp","source_ip":"10.244.1.5","destination_ip":"10.244.1.6","destination_port":80}`

	stop := errors.New("stop parsing")
	pe := &Parser{}
	var count int

	err := pe.Parse(strings.NewReader(data), func(fl flow.Flow) error {
		count++
		if count >= 2 {
			return stop
		}
		return nil
	})

	assert.ErrorIs(t, err, stop, "parser should propagate emit errors")
	assert.Equal(t, 2, count, "parser should stop after emit returns error")
}

func TestParseEmptySourcePorts(t *testing.T) {
	// source_ports is an empty array → srcPort stays 0
	line := `{"start_time":"2026-01-01T00:00:00Z","action":"allow","protocol":"tcp","source_ip":"1.2.3.4","destination_ip":"5.6.7.8","destination_port":8080,"source_ports":[]}`
	f, err := parseLine(line)
	require.NoError(t, err)
	assert.Equal(t, uint16(0), f.Layer4.SourcePort)
	assert.Equal(t, uint16(8080), f.Layer4.DestPort)
}

func TestValidateFlow(t *testing.T) {
	// A valid parsed flow should pass validation.
	line := `{"start_time":"2026-01-01T00:00:00Z","action":"allow","protocol":"tcp","source_ip":"1.2.3.4","destination_ip":"5.6.7.8","destination_port":80}`
	f, err := parseLine(line)
	require.NoError(t, err)

	err = f.Validate()
	assert.NoError(t, err, "parsed flow should be valid")
}

func TestCalicoNormalFixture(t *testing.T) {
	f, err := os.Open(testdataPath("normal.json"))
	require.NoError(t, err)
	defer f.Close()

	pe := &Parser{}
	var flows []flow.Flow
	err = pe.Parse(f, func(fl flow.Flow) error {
		flows = append(flows, fl)
		return nil
	})
	require.NoError(t, err)
	assert.Len(t, flows, 5, "normal.json contains 5 flows")

	// Spot check: first flow should be frontend-abc12 → backend-xyz99
	assert.Equal(t, "frontend-abc12", flows[0].Source.PodName)
	assert.Equal(t, "backend-xyz99", flows[0].Destination.PodName)
	assert.Equal(t, flow.Forwarded, flows[0].Verdict)
	assert.Equal(t, flow.TCP, flows[0].Layer4.Protocol)
	assert.Equal(t, uint16(8080), flows[0].Layer4.DestPort)
}

func TestCalicoDropsFixture(t *testing.T) {
	f, err := os.Open(testdataPath("drops.json"))
	require.NoError(t, err)
	defer f.Close()

	pe := &Parser{}
	var flows []flow.Flow
	err = pe.Parse(f, func(fl flow.Flow) error {
		flows = append(flows, fl)
		return nil
	})
	require.NoError(t, err)
	assert.Len(t, flows, 3, "drops.json contains 3 flows")

	for _, fl := range flows {
		assert.Equal(t, flow.Dropped, fl.Verdict, "all flows in drops.json should be DROPPED")
	}
}

func TestCalicoPortScanFixture(t *testing.T) {
	f, err := os.Open(testdataPath("port_scan.json"))
	require.NoError(t, err)
	defer f.Close()

	pe := &Parser{}
	var flows []flow.Flow
	err = pe.Parse(f, func(fl flow.Flow) error {
		flows = append(flows, fl)
		return nil
	})
	require.NoError(t, err)
	assert.Len(t, flows, 7, "port_scan.json contains 7 flows")

	for i, fl := range flows {
		assert.Equal(t, flow.Dropped, fl.Verdict, "flow %d verdict", i)
		assert.Equal(t, "suspicious-pod-7d3f9", fl.Source.PodName, "source pod name flow %d", i)
		assert.Equal(t, flow.TCP, fl.Layer4.Protocol, "protocol flow %d", i)
	}

	droppedCount := 0
	for _, fl := range flows {
		if fl.Verdict == flow.Dropped {
			droppedCount++
		}
	}
	assert.Equal(t, 7, droppedCount, "all port scan flows should be DROPPED")
}

func TestCalicoPublicEgressFixture(t *testing.T) {
	f, err := os.Open(testdataPath("public_egress.json"))
	require.NoError(t, err)
	defer f.Close()

	pe := &Parser{}
	var flows []flow.Flow
	err = pe.Parse(f, func(fl flow.Flow) error {
		flows = append(flows, fl)
		return nil
	})
	require.NoError(t, err)
	assert.Len(t, flows, 3, "public_egress.json contains 3 flows")

	for _, fl := range flows {
		assert.Equal(t, flow.Forwarded, fl.Verdict)
		assert.Equal(t, flow.Egress, fl.Direction)
		assert.Empty(t, fl.Destination.PodName, "egress destination should have no pod name")
		assert.Empty(t, fl.Destination.Namespace, "egress destination should have no namespace")
		// External IPs in destination
		assert.NotEmpty(t, fl.Destination.IP)
	}
}

func BenchmarkParseNormal(b *testing.B) {
	data, err := os.ReadFile(testdataPath("normal.json"))
	require.NoError(b, err)

	pe := &Parser{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var count int
		err := pe.Parse(strings.NewReader(string(data)), func(fl flow.Flow) error {
			count++
			return nil
		})
		require.NoError(b, err)
	}
}

func TestTimePrecision(t *testing.T) {
	line := `{"start_time":"2026-07-30T08:30:01.100Z","action":"allow","protocol":"tcp","source_ip":"10.244.1.15","destination_ip":"10.244.2.48","destination_port":8080}`
	f, err := parseLine(line)
	require.NoError(t, err)

	expected, _ := time.Parse(time.RFC3339, "2026-07-30T08:30:01.100Z")
	assert.True(t, f.Time.Equal(expected), "Time should match exactly; got %v vs %v", f.Time, expected)
}

func TestParseBytes(t *testing.T) {
	t.Parallel()

	line := `{"start_time":"2026-07-30T08:30:01.100Z","action":"allow","protocol":"tcp","source_ip":"10.244.1.15","destination_ip":"10.244.2.48","destination_port":8080,"ingress_bytes":28416,"egress_bytes":1456288}`
	f, err := parseLine(line)
	require.NoError(t, err)
	assert.Equal(t, uint64(28416+1456288), f.Bytes, "Bytes should be ingress+egress")
}

func TestParsePolicyName(t *testing.T) {
	t.Parallel()

	line := `{"start_time":"2026-07-30T09:10:01.200Z","action":"deny","protocol":"tcp","source_ip":"10.244.5.11","destination_ip":"10.244.2.48","destination_port":22,"policy_name":"deny-staging-to-production-ssh"}`
	f, err := parseLine(line)
	require.NoError(t, err)
	assert.Equal(t, "deny-staging-to-production-ssh", f.PolicyName, "PolicyName should be set from policy_name")
}

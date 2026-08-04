package calico

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/flowguarder/flowguarder/pkg/flow"
	"github.com/flowguarder/flowguarder/pkg/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile-time interface check.
var _ parser.Parser = (*SyslogParser)(nil)

var (
	// Valid syslog line (line 1 of syslog_normal.jsonl).
	syslogValid = `<14>Jul 30 08:30:01 calico-node-01 calico-flow: {"start_time":"2026-07-30T08:30:01.100Z","end_time":"2026-07-30T08:32:15.400Z","source_name":"frontend-abc12","source_namespace":"default","source_namespace_selector":"","source_selectors":{},"source_service_account":"default","source_cidr":"10.244.1.15/32","source_net":{"name":"frontend-abc12","namespace":"default","service_account":"default"},"destination_name":"backend-xyz99","destination_namespace":"production","destination_namespace_selector":"","destination_selectors":{},"destination_service_account":"backend-sa","destination_cidr":"10.244.2.48/32","destination_net":{"name":"backend-xyz99","namespace":"production","service_account":"backend-sa"},"source_ports":[],"protocol":"TCP","destination_port":8080,"action":"allow","start":"2026-07-30T08:30:01.100Z","end":"2026-07-30T08:32:15.400Z","source_ip":"10.244.1.15","destination_ip":"10.244.2.48","ingress_bytes":28416,"egress_bytes":1456288,"ingress_packets":24,"egress_packets":1028,"reported_by":"node"}`
	// Syslog deny line (line 1 of syslog_drops.jsonl).
	syslogDrop = `<14>Jul 30 09:10:01 calico-node-01 calico-flow: {"start_time":"2026-07-30T09:10:01.200Z","end_time":"2026-07-30T09:10:01.400Z","source_name":"web-f8a2b","source_namespace":"staging","source_namespace_selector":"","source_selectors":{},"source_service_account":"default","source_cidr":"10.244.5.11/32","source_net":{"name":"web-f8a2b","namespace":"staging","service_account":"default"},"destination_name":"backend-xyz99","destination_namespace":"production","destination_namespace_selector":"","destination_selectors":{},"destination_service_account":"backend-sa","destination_cidr":"10.244.2.48/32","destination_net":{"name":"backend-xyz99","namespace":"production","service_account":"backend-sa"},"source_ports":[],"protocol":"TCP","destination_port":22,"action":"deny","start":"2026-07-30T09:10:01.200Z","end":"2026-07-30T09:10:01.400Z","source_ip":"10.244.5.11","destination_ip":"10.244.2.48","ingress_bytes":0,"egress_bytes":54,"ingress_packets":0,"egress_packets":1,"reported_by":"controller","policy_name":"deny-staging-to-production-ssh","policy_type":"egress"}`
)

// syslogTestFixture returns the filesystem path to a testdata/calico fixture.
func syslogTestFixture(name string) string {
	return filepath.Join("..", "..", "..", "testdata", "calico", name)
}

func TestSyslogParserSource(t *testing.T) {
	p := &SyslogParser{}
	assert.Equal(t, parser.SourceCalicoSyslog, p.Source())
}

func TestExtractJSONFromSyslog(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantErr bool
		check   func(t *testing.T, jsonPart string)
	}{
		{
			name: "valid syslog with JSON",
			line: syslogValid,
			check: func(t *testing.T, jsonPart string) {
				assert.Contains(t, jsonPart, `"start_time"`)
				assert.Contains(t, jsonPart, `"source_name":"frontend-abc12"`)
			},
		},
		{
			name: "valid syslog deny line",
			line: syslogDrop,
			check: func(t *testing.T, jsonPart string) {
				assert.Contains(t, jsonPart, `"action":"deny"`)
				assert.Contains(t, jsonPart, `"source_ip":"10.244.5.11"`)
			},
		},
		{
			name:    "no priority field",
			line:    "Jul 30 08:30:01 host app: message",
			wantErr: true,
		},
		{
			name:    "no header-message separator",
			line:    "<14>Jul 30 08:30:01 calico-node-01 calico-flow",
			wantErr: true,
		},
		{
			name:    "empty message after header",
			line:    "<14>Jul 30 08:30:01 host app: ",
			wantErr: true,
		},
		{
			name:    "non-JSON message",
			line:    "<14>Jul 30 08:30:01 host app: plain text",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractJSONFromSyslog(tt.line)
			if tt.wantErr {
				assert.Error(t, err)
				var fe *parser.FormatError
				require.True(t, errors.As(err, &fe), "error should be *FormatError, got %T", err)
				assert.Equal(t, parser.SourceCalicoSyslog, fe.Source)
				return
			}
			require.NoError(t, err)
			if tt.check != nil {
				tt.check(t, got)
			}
		})
	}
}

func TestSyslogParserValidNormalFixture(t *testing.T) {
	f, err := os.Open(syslogTestFixture("syslog_normal.jsonl"))
	require.NoError(t, err)
	defer f.Close()

	p := &SyslogParser{}
	var flows []flow.Flow
	err = p.Parse(f, func(fl flow.Flow) error {
		flows = append(flows, fl)
		return nil
	})
	require.NoError(t, err)
	assert.Len(t, flows, 3, "syslog_normal.jsonl should yield 3 flows")

	assert.Equal(t, "frontend-abc12", flows[0].Source.PodName)
	assert.Equal(t, flow.Forwarded, flows[0].Verdict)
	assert.Equal(t, flow.TCP, flows[0].Layer4.Protocol)
	assert.Equal(t, uint16(8080), flows[0].Layer4.DestPort)
}

func TestSyslogParserValidDropsFixture(t *testing.T) {
	f, err := os.Open(syslogTestFixture("syslog_drops.jsonl"))
	require.NoError(t, err)
	defer f.Close()

	p := &SyslogParser{}
	var flows []flow.Flow
	err = p.Parse(f, func(fl flow.Flow) error {
		flows = append(flows, fl)
		return nil
	})
	require.NoError(t, err)
	assert.Len(t, flows, 3, "syslog_drops.jsonl should yield 3 flows")

	for i, fl := range flows {
		assert.Equal(t, flow.Dropped, fl.Verdict, "flow %d verdict", i)
		assert.Equal(t, flow.TCP, fl.Layer4.Protocol, "flow %d protocol", i)
	}
}

func TestSyslogParserMalformedHeader(t *testing.T) {
	line := "plain text no syslog header at all\n"
	p := &SyslogParser{}
	var flows []flow.Flow
	err := p.Parse(strings.NewReader(line), func(fl flow.Flow) error {
		flows = append(flows, fl)
		return nil
	})
	require.NoError(t, err)
	assert.Empty(t, flows, "malformed syslog line should be skipped")
}

func TestSyslogParserInvalidJSONPayload(t *testing.T) {
	line := `<14>Jul 30 08:30:01 host app: {invalid json` + "\n"
	p := &SyslogParser{}
	var flows []flow.Flow
	err := p.Parse(strings.NewReader(line), func(fl flow.Flow) error {
		flows = append(flows, fl)
		return nil
	})
	require.NoError(t, err)
	assert.Empty(t, flows, "syslog with invalid JSON should be skipped")
}

func TestSyslogParserMultipleLinesMixed(t *testing.T) {
	input := syslogValid + "\n" + syslogDrop + "\n\n" + "bad line\n"
	p := &SyslogParser{}
	var flows []flow.Flow
	err := p.Parse(strings.NewReader(input), func(fl flow.Flow) error {
		flows = append(flows, fl)
		return nil
	})
	require.NoError(t, err)
	assert.Len(t, flows, 2, "two valid syslog lines should parse")

	assert.Equal(t, "frontend-abc12", flows[0].Source.PodName)
	assert.Equal(t, flow.Forwarded, flows[0].Verdict)

	assert.Equal(t, "web-f8a2b", flows[1].Source.PodName)
	assert.Equal(t, flow.Dropped, flows[1].Verdict)
}

func TestSyslogParserEmitErrorStops(t *testing.T) {
	input := syslogValid + "\n" + syslogDrop + "\n"
	stop := errors.New("stop")
	p := &SyslogParser{}
	count := 0

	err := p.Parse(strings.NewReader(input), func(fl flow.Flow) error {
		count++
		if count >= 1 {
			return stop
		}
		return nil
	})

	assert.ErrorIs(t, err, stop)
	assert.Equal(t, 1, count, "should stop after first emit")
}

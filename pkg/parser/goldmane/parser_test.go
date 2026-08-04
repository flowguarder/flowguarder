package goldmane

import (
	"strings"
	"testing"
	"time"

	"github.com/flowguarder/flowguarder/pkg/flow"
	"github.com/flowguarder/flowguarder/pkg/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------- TestParser_Source ----------

func TestParser_Source(t *testing.T) {
	t.Parallel()

	p := &Parser{}
	if got := p.Source(); got != parser.SourceGoldmane {
		t.Fatalf("Source() = %v, want %v", got, parser.SourceGoldmane)
	}
}

// ---------- TestParser_Parse_ValidSingleRecord ----------

func TestParser_Parse_ValidSingleRecord(t *testing.T) {
	t.Parallel()

	input := `{
		"id": "1",
		"flow": {
			"Key": {
				"sourceName": "frontend-abc12def-*",
				"sourceNamespace": "default",
				"destName": "backend-xyz99-*",
				"destNamespace": "production",
				"destPort": "443",
				"proto": "tcp",
				"reporter": "Dst",
				"action": "Allow"
			},
			"startTime": "1700000000",
			"bytesIn": "2048",
			"bytesOut": "1024",
			"packetsIn": "10",
			"packetsOut": "5"
		}
	}`

	p := &Parser{}
	var emitted []flow.Flow

	err := p.Parse(strings.NewReader(input), func(f flow.Flow) error {
		emitted = append(emitted, f)
		return nil
	})

	require.NoError(t, err)
	require.Len(t, emitted, 1)

	f := emitted[0]

	expectedTime := time.Unix(1700000000, 0).UTC()
	require.True(t, f.Time.Equal(expectedTime), "Time %v != %v", f.Time, expectedTime)
	require.Equal(t, flow.Forwarded, f.Verdict, "Allow → Forwarded")
	require.Equal(t, flow.Ingress, f.Direction, "Dst reporter → Ingress")
	require.Equal(t, "default", f.Source.Namespace)
	require.Equal(t, "frontend-abc12def", f.Source.PodName, "strip trailing -*")
	require.Equal(t, "production", f.Destination.Namespace)
	require.Equal(t, "backend-xyz99", f.Destination.PodName, "strip trailing -*")
	require.Equal(t, uint16(443), f.Layer4.DestPort)
	require.Equal(t, flow.TCP, f.Layer4.Protocol)
	require.Equal(t, uint64(3072), f.Bytes, "2048+1024 bytes")
	require.Equal(t, uint64(15), f.Packets, "10+5 packets")
}

// ---------- TestParser_Parse_MultipleRecords ----------

func TestParser_Parse_MultipleRecords(t *testing.T) {
	t.Parallel()

	input := `{
		"id": "1",
		"flow": {
			"Key": {
				"sourceName": "a",
				"sourceNamespace": "ns",
				"destName": "b",
				"destNamespace": "ns",
				"destPort": "53",
				"proto": "udp",
				"reporter": "Dst",
				"action": "Allow"
			}
		}
	}
	{
		"id": "2",
		"flow": {
			"Key": {
				"sourceName": "c",
				"sourceNamespace": "ns",
				"destName": "d",
				"destNamespace": "ns",
				"destPort": "22",
				"proto": "tcp",
				"reporter": "Src",
				"action": "Deny"
			}
		}
	}
	{
		"id": "3",
		"flow": {
			"Key": {
				"sourceName": "e",
				"sourceNamespace": "ns",
				"destName": "f",
				"destNamespace": "ns",
				"destPort": "80",
				"proto": "tcp",
				"reporter": "Dst",
				"action": "Pass"
			}
		}
	}`

	p := &Parser{}
	var emitted []flow.Flow

	err := p.Parse(strings.NewReader(input), func(f flow.Flow) error {
		emitted = append(emitted, f)
		return nil
	})

	require.NoError(t, err)
	require.Len(t, emitted, 3)

	// Flow 0 — Allow/Dst/UDP
	require.Equal(t, flow.Forwarded, emitted[0].Verdict)
	require.Equal(t, flow.Ingress, emitted[0].Direction)
	require.Equal(t, flow.UDP, emitted[0].Layer4.Protocol)
	require.Equal(t, uint16(53), emitted[0].Layer4.DestPort)

	// Flow 1 — Deny/Src/TCP
	require.Equal(t, flow.Dropped, emitted[1].Verdict)
	require.Equal(t, flow.Egress, emitted[1].Direction)
	require.Equal(t, flow.TCP, emitted[1].Layer4.Protocol)
	require.Equal(t, uint16(22), emitted[1].Layer4.DestPort)

	// Flow 2 — Pass/Dst/TCP
	require.Equal(t, flow.Forwarded, emitted[2].Verdict) // Pass → Forwarded
	require.Equal(t, flow.Ingress, emitted[2].Direction) // Dst → Ingress
	require.Equal(t, flow.TCP, emitted[2].Layer4.Protocol)
	require.Equal(t, uint16(80), emitted[2].Layer4.DestPort)
}

// ---------- TestParser_Parse_TruncatedTrailingRecord ----------

func TestParser_Parse_TruncatedTrailingRecord(t *testing.T) {
	t.Parallel()

	oneValid := `{
		"id": "1",
		"flow": {
			"Key": {
				"sourceName": "valid-pod",
				"sourceNamespace": "default",
				"destName": "valid-svc",
				"destNamespace": "prod",
				"destPort": "443",
				"proto": "tcp",
				"reporter": "Dst",
				"action": "Allow"
			},
			"startTime": "1700000000"
		}
	}`
	// A truncated JSON fragment after a newline causes json.Decoder.More()/Decode() to fail.
	truncated := `{"id":"2", "flow"`

	input := oneValid + "\n" + truncated

	p := &Parser{}
	var emitted []flow.Flow

	err := p.Parse(strings.NewReader(input), func(f flow.Flow) error {
		emitted = append(emitted, f)
		return nil
	})

	require.NoError(t, err, "Parse should not return error on truncated tail")
	require.Len(t, emitted, 1, "only the complete record should be emitted")
}

// ---------- TestParser_Parse_EmptyInput ----------

func TestParser_Parse_EmptyInput(t *testing.T) {
	t.Parallel()

	p := &Parser{}
	var emitted []flow.Flow

	err := p.Parse(strings.NewReader(""), func(flow.Flow) error {
		return nil
	})

	require.NoError(t, err)
	require.Empty(t, emitted, "emit must not be called for empty input")
}

// ---------- TestParser_Parse_MissingFlowField ----------

func TestParser_Parse_MissingFlowField(t *testing.T) {
	t.Parallel()

	// Valid JSON but no "flow" key → mapFlowResult logs and skips.
	input := `{"id":"1"}`

	p := &Parser{}
	var emitted []flow.Flow

	err := p.Parse(strings.NewReader(input), func(f flow.Flow) error {
		emitted = append(emitted, f)
		return nil
	})

	require.NoError(t, err)
	require.Empty(t, emitted, "emit must not be called when 'flow' field is missing")
}

// ---------- TestParser_Parse_UnknownAction ----------

func TestParser_Parse_UnknownAction(t *testing.T) {
	t.Parallel()

	input := `{
		"id": "1",
		"flow": {
			"Key": {
				"sourceName": "test-src",
				"sourceNamespace": "default",
				"destName": "test-dst",
				"destNamespace": "prod",
				"destPort": "8080",
				"proto": "tcp",
				"reporter": "Src",
				"action": "Monitor"
			},
			"startTime": "1700000000"
		}
	}`

	p := &Parser{}
	var emitted []flow.Flow

	err := p.Parse(strings.NewReader(input), func(f flow.Flow) error {
		emitted = append(emitted, f)
		return nil
	})

	require.NoError(t, err)
	require.Len(t, emitted, 1)

	// "Monitor" is not in {Allow,Deny,Pass} → mapAction falls through to default flow.Allow
	require.Equal(t, flow.Allow, emitted[0].Verdict)
}

// ---------- TestParser_Parse_NumericStrings ----------

func TestParser_Parse_NumericStrings(t *testing.T) {
	t.Parallel()

	input := `{
		"id": "1",
		"flow": {
			"Key": {
				"sourceName": "a",
				"sourceNamespace": "default",
				"destName": "b",
				"destNamespace": "default",
				"destPort": "443",
				"proto": "udp",
				"reporter": "Dst",
				"action": "Allow"
			},
			"startTime": "1625097600",
			"packetsIn": "42",
			"packetsOut": "21",
			"bytesIn": "10240",
			"bytesOut": "20480"
		}
	}`

	p := &Parser{}
	var emitted []flow.Flow

	err := p.Parse(strings.NewReader(input), func(f flow.Flow) error {
		emitted = append(emitted, f)
		return nil
	})

	require.NoError(t, err)
	require.Len(t, emitted, 1)

	f := emitted[0]

	expTime := time.Unix(1625097600, 0).UTC()
	require.True(t, f.Time.Equal(expTime), "Time %v != %v", f.Time, expTime)
	require.Equal(t, uint16(443), f.Layer4.DestPort)
	require.Equal(t, flow.UDP, f.Layer4.Protocol)
	require.Equal(t, uint64(30720), f.Bytes, "10240+20480")
	require.Equal(t, uint64(63), f.Packets, "42+21")
}

// ---------- TestParser_Parse_WorkloadNameStrip ----------

func TestParser_Parse_WorkloadNameStrip(t *testing.T) {
	t.Parallel()

	input := `{
		"id": "1",
		"flow": {
			"Key": {
				"sourceName": "frontend-abc12def-*",
				"sourceNamespace": "default",
				"destName": "backend-xyz99-*",
				"destNamespace": "production",
				"destPort": "8080",
				"proto": "tcp",
				"reporter": "Dst",
				"action": "Allow"
			},
			"startTime": "1700000000"
		}
	}`

	p := &Parser{}
	var emitted []flow.Flow

	err := p.Parse(strings.NewReader(input), func(f flow.Flow) error {
		emitted = append(emitted, f)
		return nil
	})

	require.NoError(t, err)
	require.Len(t, emitted, 1)

	f := emitted[0]

	require.Equal(t, "frontend-abc12def", f.Source.PodName,
		"sourceName trailing -* stripped")
	require.Equal(t, "backend-xyz99", f.Destination.PodName,
		"destName trailing -* stripped")
}

// ---------- TestParser_Parse_LabelsParsing ----------

func TestParser_Parse_LabelsParsing(t *testing.T) {
	t.Parallel()

	input := `{
		"id": "1",
		"flow": {
			"Key": {
				"sourceName": "src",
				"sourceNamespace": "default",
				"destName": "dst",
				"destNamespace": "default",
				"destPort": "443",
				"proto": "tcp",
				"reporter": "Dst",
				"action": "Allow"
			},
			"startTime": "1700000000",
			"sourceLabels": ["app=x", "k8s-app=y"],
			"destLabels": ["tier=frontend", "version=v2"]
		}
	}`

	p := &Parser{}
	var emitted []flow.Flow

	err := p.Parse(strings.NewReader(input), func(f flow.Flow) error {
		emitted = append(emitted, f)
		return nil
	})

	require.NoError(t, err)
	require.Len(t, emitted, 1)

	f := emitted[0]

	require.Equal(t, map[string]string{
		"app":     "x",
		"k8s-app": "y",
	}, f.SourceLabels)

	require.Equal(t, map[string]string{
		"tier":    "frontend",
		"version": "v2",
	}, f.DestLabels)

	// Endpoint Labels populated with same map as shortcut fields.
	require.Equal(t, map[string]string{
		"app":     "x",
		"k8s-app": "y",
	}, f.Source.Labels)

	require.Equal(t, map[string]string{
		"tier":    "frontend",
		"version": "v2",
	}, f.Destination.Labels)
}

func TestParsePolicyNameFromDeny(t *testing.T) {
	t.Parallel()

	input := `{
		"id": "1",
		"flow": {
			"Key": {
				"sourceName": "frontend-abc",
				"sourceNamespace": "default",
				"destName": "backend-xyz",
				"destNamespace": "production",
				"destPort": "443",
				"proto": "tcp",
				"reporter": "Dst",
				"action": "Deny",
				"policies": {
					"enforcedPolicies": [
						{"name": "kns.default/default-deny", "action": "Allow"},
						{"name": "kns.production/backend-deny-ssh", "action": "Deny"}
					],
					"pendingPolicies": []
				}
			}
		}
	}`

	p := &Parser{}
	var emitted []flow.Flow

	err := p.Parse(strings.NewReader(input), func(f flow.Flow) error {
		emitted = append(emitted, f)
		return nil
	})

	require.NoError(t, err)
	require.Len(t, emitted, 1)
	assert.Equal(t, "kns.production/backend-deny-ssh",
		emitted[0].PolicyName,
		"PolicyName should be the first Deny in enforcedPolicies")
}

func TestParsePolicyNameFallbackToFirstEnforced(t *testing.T) {
	t.Parallel()

	input := `{
		"id": "1",
		"flow": {
			"Key": {
				"sourceName": "frontend-abc",
				"sourceNamespace": "default",
				"destName": "backend-xyz",
				"destNamespace": "production",
				"destPort": "80",
				"proto": "tcp",
				"reporter": "Dst",
				"action": "Allow",
				"policies": {
					"enforcedPolicies": [
						{"name": "kns.default/allow-http", "action": "Allow"},
						{"name": "kns.production/backend-policy", "action": "Allow"}
					]
				}
			}
		}
	}`

	p := &Parser{}
	var emitted []flow.Flow

	err := p.Parse(strings.NewReader(input), func(f flow.Flow) error {
		emitted = append(emitted, f)
		return nil
	})

	require.NoError(t, err)
	require.Len(t, emitted, 1)
	assert.Equal(t, "kns.default/allow-http",
		emitted[0].PolicyName,
		"PolicyName should fallback to first enforced policy when no Deny")
}

func TestParsePolicyNameEmptyPolicies(t *testing.T) {
	t.Parallel()

	input := `{
		"id": "1",
		"flow": {
			"Key": {
				"sourceName": "frontend-abc",
				"sourceNamespace": "default",
				"destName": "backend-xyz",
				"destNamespace": "production",
				"destPort": "80",
				"proto": "tcp",
				"reporter": "Dst",
				"action": "Allow"
			}
		}
	}`

	p := &Parser{}
	var emitted []flow.Flow

	err := p.Parse(strings.NewReader(input), func(f flow.Flow) error {
		emitted = append(emitted, f)
		return nil
	})

	require.NoError(t, err)
	require.Len(t, emitted, 1)
	assert.Empty(t, emitted[0].PolicyName, "PolicyName should be empty when no policies field")
}

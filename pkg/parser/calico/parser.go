// Package calico provides a streaming newline-delimited JSON parser for
// Calico aggregated flow log records.
package calico

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/flowguarder/flowguarder/pkg/flow"
	"github.com/flowguarder/flowguarder/pkg/parser"
)

// parserLogger logs parser-level warnings (skipped records, malformed lines).
var parserLogger = log.New(&discardWriter{}, "", log.LstdFlags)

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

// calicoRecord mirrors the essential fields of a Calico aggregated flow log
// JSON object. Only the fields we actually need are defined.
type calicoRecord struct {
	StartTime string           `json:"start_time"`
	Action    string           `json:"action"`
	Proto     string           `json:"protocol"`
	SrcName   string           `json:"source_name"`
	SrcNS     string           `json:"source_namespace"`
	SrcIP     string           `json:"source_ip"`
	SrcPorts  []interface{}    `json:"source_ports"`
	SrcLabels json.RawMessage  `json:"source_labels"`
	DstName   string           `json:"destination_name"`
	DstNS     string           `json:"destination_namespace"`
	DstIP     string           `json:"destination_ip"`
	DstPort   uint64            `json:"destination_port"`
	DstLabels json.RawMessage  `json:"dest_labels"`
	IngressBytes uint64         `json:"ingress_bytes"`
	EgressBytes uint64          `json:"egress_bytes"`
	PolicyName  string          `json:"policy_name"`
	PolicyType  string          `json:"policy_type"`
}

// sourceLabels wraps the Calico "source_labels" / "dest_labels" shape:
// {"labels": ["key=value", ...]}
type sourceLabels struct {
	Labels []string `json:"labels"`
}

// parseLabels converts a []string of "k=v" entries into a map[string]string.
func parseLabels(raw []string) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	m := make(map[string]string, len(raw))
	for _, kv := range raw {
		if i := strings.IndexByte(kv, '='); i > 0 {
			m[kv[:i]] = kv[i+1:]
		}
	}
	return m
}

// Parser implements parser.Parser for Calico aggregated flow logs.
type Parser struct{}

// Source returns the source identifier for this parser.
func (p *Parser) Source() parser.Source {
	return parser.SourceCalico
}

// Parse reads newline-delimited JSON records from r, maps each into a
// [flow.Flow], and passes it to emit. It returns nil on success.
func (p *Parser) Parse(r io.Reader, emit func(flow.Flow) error) error {
	scanner := bufio.NewScanner(r)
	// Increase buffer for potentially long Calico records.
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		f, err := parseLine(line)
		if err != nil {
			// On parse error, skip the line and continue.
			parserLogger.Printf("skipping line: %v", err)
			continue
		}

		if err := emit(f); err != nil {
			return err
		}
	}

	return scanner.Err()
}

// parseLine decodes a single JSON line into a flow.Flow.
func parseLine(line string) (flow.Flow, error) {
	// Use json.Decoder for streaming from a string reader.
	dec := json.NewDecoder(strings.NewReader(line))
	dec.UseNumber()

	var rec calicoRecord
	if err := dec.Decode(&rec); err != nil {
		return flow.Flow{}, &parser.FormatError{Source: parser.SourceCalico, Message: err.Error()}
	}

	f, err := mapRecord(rec)
	if err != nil {
		return flow.Flow{}, &parser.FormatError{Source: parser.SourceCalico, Message: err.Error()}
	}
	return f, nil
}

// mapRecord transforms a calicoRecord into a canonical flow.Flow.
func mapRecord(rec calicoRecord) (flow.Flow, error) {
	// time: required
	if rec.StartTime == "" {
		return flow.Flow{}, fmt.Errorf("missing required field start_time")
	}
	t, err := parseTime(rec.StartTime)
	if err != nil {
		return flow.Flow{}, fmt.Errorf("parsing start_time %q: %w", rec.StartTime, err)
	}

	// verdict: required
	v, err := mapVerdict(rec.Action)
	if err != nil {
		return flow.Flow{}, fmt.Errorf("parsing action %q: %w", rec.Action, err)
	}

	// protocol
	proto := mapProtocol(rec.Proto)

	// source endpoint
	src := flow.Endpoint{
		PodName:  rec.SrcName,
		Namespace: rec.SrcNS,
		IP:       rec.SrcIP,
	}
	if rec.SrcLabels != nil {
		src.Labels = parseSourceLabels(rec.SrcLabels)
	}

	// Determine source port. Calico stores source_ports as a JSON array.
	srcPort := uint16(0)
	if len(rec.SrcPorts) > 0 {
		// Expect first element to be a number.
		switch v := rec.SrcPorts[0].(type) {
		case float64:
			srcPort = uint16(v)
		case string:
			var n uint64
			_, err := fmt.Sscanf(v, "%d", &n)
			if err == nil {
				srcPort = uint16(n)
			}
		}
	}

	// destination endpoint
	dst := flow.Endpoint{
		PodName:  rec.DstName,
		Namespace: rec.DstNS,
		IP:       rec.DstIP,
	}
	if rec.DstLabels != nil {
		dst.Labels = parseSourceLabels(rec.DstLabels)
	}

	// direction: if destination_name is empty, traffic goes to an external IP → Egress.
	dir := directionFromRecord(rec)

	f := flow.Flow{
		Time:       t,
		Source:     src,
		Destination: dst,
		Layer4: flow.Layer4{
			SourcePort: srcPort,
			DestPort:   uint16(rec.DstPort),
			Protocol:   proto,
		},
		Verdict:   v,
		Direction: dir,
		Bytes:     rec.IngressBytes + rec.EgressBytes,
		IsReply:   false,
	}

	if rec.PolicyName != "" {
		f.PolicyName = rec.PolicyName
	}

	_ = rec.PolicyType // reserved for future use

	// Validate required fields.
	if err := f.Validate(); err != nil {
		return flow.Flow{}, fmt.Errorf("validating flow: %w", err)
	}

	return f, nil
}

// parseTime parses an RFC3339 timestamp.
func parseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}

// mapVerdict maps Calico action strings to flow.Verdict.
func mapVerdict(action string) (flow.Verdict, error) {
	switch strings.ToLower(action) {
	case "allow":
		return flow.Forwarded, nil
	case "deny":
		return flow.Dropped, nil
	default:
		return "", fmt.Errorf("unknown action %q", action)
	}
}

// mapProtocol normalizes Calico protocol strings to canonical form.
func mapProtocol(proto string) flow.Protocol {
	switch strings.ToUpper(proto) {
	case "TCP":
		return flow.TCP
	case "UDP":
		return flow.UDP
	case "ICMP":
		return flow.ICMP
	case "SCTP":
		return flow.SCTP
	default:
		return flow.ANY_P
	}
}

// directionFromRecord infers traffic direction.
func directionFromRecord(rec calicoRecord) flow.Direction {
	if rec.DstName == "" && rec.DstNS == "" {
		return flow.Egress
	}
	return flow.Ingress
}

// parseSourceLabels attempts to parse raw JSON into a map from "k=v" strings.
func parseSourceLabels(raw json.RawMessage) map[string]string {
	var sl sourceLabels
	if err := json.Unmarshal(raw, &sl); err != nil {
		parserLogger.Printf("skipping unparseable labels: %v", err)
		return nil
	}
	return parseLabels(sl.Labels)
}

// init registers the Parser for auto-detection via SelectParser.
func init() {
	parser.RegisterParser(parser.SourceCalico, func() parser.Parser { return &Parser{} })
}

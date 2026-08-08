// Package goldmane provides a streaming JSON parser for Calico Goldmane
// FlowResult messages. Each top-level JSON object is one flow.
package goldmane

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/flowguarder/flowguarder/pkg/flow"
	"github.com/flowguarder/flowguarder/pkg/parser"
)

// parserLogger logs parser-level warnings (skipped records, malformed data).
var parserLogger = log.New(&discardWriter{}, "", log.LstdFlags)

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

// flowResultJSON mirrors the top-level Goldmane FlowResult proto3 JSON.
type flowResultJSON struct {
	ID   string    `json:"id"`
	Flow *flowJSON `json:"flow"`
}

// flowJSON mirrors the nested "flow" object inside FlowResult.
type flowJSON struct {
	Key                     *flowKeyJSON `json:"Key"`
	StartTime               string       `json:"startTime"`
	EndTime                 string       `json:"endTime"`
	SourceLabels            []string     `json:"sourceLabels"`
	DestLabels              []string     `json:"destLabels"`
	PacketsIn               string       `json:"packetsIn"`
	PacketsOut              string       `json:"packetsOut"`
	BytesIn                 string       `json:"bytesIn"`
	BytesOut                string       `json:"bytesOut"`
	NumConnectionsStarted   string       `json:"numConnectionsStarted"`
	NumConnectionsCompleted string       `json:"numConnectionsCompleted"`
	NumConnectionsLive      string       `json:"numConnectionsLive"`
}

// flowKeyJSON mirrors the Key nested object.
type flowKeyJSON struct {
	SourceName      string          `json:"sourceName"`
	SourceNamespace string          `json:"sourceNamespace"`
	SourceType      string          `json:"sourceType"`
	DestName        string          `json:"destName"`
	DestNamespace   string          `json:"destNamespace"`
	DestType        string          `json:"destType"`
	DestPort        string          `json:"destPort"`
	Proto           string          `json:"proto"`
	Reporter        string          `json:"reporter"`
	Action          string          `json:"action"`
	Policies        json.RawMessage `json:"policies"`
}

// ---------- parse helpers ----------

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

// stripPodSuffix trims a trailing "-<hash>" segment from a Kubernetes pod name,
// e.g. "ingress-nginx-controller-dd6fbcbc7-*" → "ingress-nginx-controller-dd6fbcbc7".
// If there is no trailing "-*" suffix, the original name is returned unchanged.
func stripPodSuffix(name string) string {
	if name == "" {
		return name
	}
	// Match pattern: pod-name-<hash>, remove only the last -<alphanumerics> suffix
	// Calico pods end with "-*" in the aggregated view so we strip up to the last '-'.
	lastDash := strings.LastIndexByte(name, '-')
	if lastDash > 0 && lastDash < len(name)-1 {
		return name[:lastDash]
	}
	return name
}

// ---------- Parser ----------

// Parser implements [parser.Parser] for Goldmane FlowResult JSON lines.
type Parser struct{}

// Source returns the source identifier for this parser.
func (p *Parser) Source() parser.Source {
	return parser.SourceGoldmane
}

// Parse reads newline-delimited JSON objects from r. Each top-level object is
// decoded as a [flowResultJSON] and mapped into a [flow.Flow] via [emit].
//
// On a decode error (e.g. truncated final record), the error is logged and
// the loop breaks; nil is returned as long as no emit error occurred.
func (p *Parser) Parse(r io.Reader, emit func(flow.Flow) error) error {
	dec := json.NewDecoder(r)

	for dec.More() {
		var result flowResultJSON
		if err := dec.Decode(&result); err != nil {
			// Log-and-skip: truncated or otherwise unparseable record.
			parserLogger.Printf("skipping record: %v", err)
			break
		}

		f, err := mapFlowResult(result)
		if err != nil {
			parserLogger.Printf("skipping record: %v", err)
			continue
		}

		if err := emit(f); err != nil {
			return err
		}
	}

	return nil
}

// ---------- mapping ----------

// mapFlowResult converts a Goldmane FlowResult into a canonical flow.Flow.
func mapFlowResult(result flowResultJSON) (flow.Flow, error) {
	if result.Flow == nil {
		return flow.Flow{}, fmt.Errorf("missing 'flow' field")
	}
	if result.Flow.Key == nil {
		return flow.Flow{}, fmt.Errorf("missing 'flow.Key' field")
	}

	key := result.Flow.Key

	// time: required
	var t time.Time
	if result.Flow.StartTime != "" {
		sec, err := strconv.ParseInt(result.Flow.StartTime, 10, 64)
		if err != nil {
			return flow.Flow{}, fmt.Errorf("parsing startTime %q: %w", result.Flow.StartTime, err)
		}
		t = time.Unix(sec, 0).UTC()
	}

	// verdict: required
	v := mapAction(key.Action)

	// protocol
	proto := mapProto(key.Proto)

	// direction
	dir := mapDirection(key.Reporter)

	// pods: strip trailing hash suffix
	srcPod := stripPodSuffix(key.SourceName)
	dstPod := stripPodSuffix(key.DestName)

	// destination port: required for Validate? No — Source.IP and Dest.IP
	// are the required IPs, verdict and direction are required too.
	var dstPort uint16
	if key.DestPort != "" {
		p, err := strconv.ParseUint(key.DestPort, 10, 16)
		if err != nil {
			return flow.Flow{}, fmt.Errorf("parsing destPort %q: %w", key.DestPort, err)
		}
		dstPort = uint16(p)
	}

	// bytes (on the flow nested object, not on Key)
	var bytes uint64
	if result.Flow.BytesIn != "" {
		bi, err := strconv.ParseUint(result.Flow.BytesIn, 10, 64)
		if err != nil {
			return flow.Flow{}, fmt.Errorf("parsing bytesIn %q: %w", result.Flow.BytesIn, err)
		}
		bytes += bi
	}
	if result.Flow.BytesOut != "" {
		bo, err := strconv.ParseUint(result.Flow.BytesOut, 10, 64)
		if err != nil {
			return flow.Flow{}, fmt.Errorf("parsing bytesOut %q: %w", result.Flow.BytesOut, err)
		}
		bytes += bo
	}

	// packets (on the flow nested object, not on Key)
	var packets uint64
	if result.Flow.PacketsIn != "" {
		pi, err := strconv.ParseUint(result.Flow.PacketsIn, 10, 64)
		if err != nil {
			return flow.Flow{}, fmt.Errorf("parsing packetsIn %q: %w", result.Flow.PacketsIn, err)
		}
		packets += pi
	}
	if result.Flow.PacketsOut != "" {
		po, err := strconv.ParseUint(result.Flow.PacketsOut, 10, 64)
		if err != nil {
			return flow.Flow{}, fmt.Errorf("parsing packetsOut %q: %w", result.Flow.PacketsOut, err)
		}
		packets += po
	}

	srcLabels := parseLabels(result.Flow.SourceLabels)
	dstLabels := parseLabels(result.Flow.DestLabels)

	f := flow.Flow{
		Time:      t,
		Verdict:   v,
		Direction: dir,
		Source: flow.Endpoint{
			Namespace: key.SourceNamespace,
			PodName:   srcPod,
			IP:        "0.0.0.0", // Goldmane doesn't expose per-flow IPs
			Labels:    srcLabels,
		},
		Destination: flow.Endpoint{
			Namespace: key.DestNamespace,
			PodName:   dstPod,
			IP:        "0.0.0.0", // Goldmane doesn't expose per-flow IPs
			Labels:    dstLabels,
		},
		Layer4: flow.Layer4{
			DestPort: dstPort,
			Protocol: proto,
		},
		Bytes:        bytes,
		Packets:      packets,
		SourceLabels: srcLabels,
		DestLabels:   dstLabels,
		IsReply:      false,
	}

	// --- PolicyName: find first Deny in enforcedPolicies, fallback first entry---
	f.PolicyName = resolvePolicyName(key.Policies)

	return f, nil
}

// policyEntryJSON mirrors a single entry inside enforcedPolicies / pendingPolicies.
type policyEntryJSON struct {
	Name   string `json:"name"`
	Action string `json:"action"`
}

// policiesJSON mirrors the policies object in flowKeyJSON.
type policiesJSON struct {
	EnforcedPolicies []policyEntryJSON `json:"enforcedPolicies"`
	PendingPolicies  []policyEntryJSON `json:"pendingPolicies"`
}

// resolvePolicyName unmarshals key.Policies and returns the name of the first
// Deny-enforced policy, or the first enforced entry if none is Deny.
func resolvePolicyName(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var p policiesJSON
	if err := json.Unmarshal(raw, &p); err != nil {
		parserLogger.Printf("skipping unparseable policies: %v", err)
		return ""
	}

	// Prefer first Deny.
	for _, ep := range p.EnforcedPolicies {
		if strings.ToLower(ep.Action) == "deny" {
			return ep.Name
		}
	}
	// Fallback: first enforced entry.
	if len(p.EnforcedPolicies) > 0 {
		return p.EnforcedPolicies[0].Name
	}
	return ""
}

// mapAction maps Goldmane action strings to flow.Verdict.
func mapAction(action string) flow.Verdict {
	switch strings.ToLower(action) {
	case "allow", "pass":
		return flow.Forwarded
	case "deny":
		return flow.Dropped
	default:
		return flow.Allow
	}
}

// mapProto normalizes Goldmane proto strings to canonical form.
func mapProto(proto string) flow.Protocol {
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
		return flow.Any
	}
}

// mapDirection maps Goldmane reporter field to flow.Direction.
func mapDirection(reporter string) flow.Direction {
	switch strings.ToLower(reporter) {
	case "src":
		return flow.Egress
	case "dst":
		return flow.Ingress
	default:
		return flow.Internal
	}
}

// init registers the Parser for auto-detection via SelectParser.
func init() {
	parser.RegisterParser(parser.SourceGoldmane, func() parser.Parser {
		return &Parser{}
	})
}

var _ parser.Parser = (*Parser)(nil)

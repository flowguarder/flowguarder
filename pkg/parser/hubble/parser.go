package hubble

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
	"github.com/flowguarder/flowguarder/pkg/flow"
	"github.com/flowguarder/flowguarder/pkg/parser"
)

const (
	// SourceHubble is the canonical source identifier for Hubble JSON.
	SourceHubble parser.Source = parser.SourceHubble
)

// Verdicts mapping from Hubble JSON verdict strings.
var verdictMap = map[string]flow.Verdict{
	"FORWARDED":  flow.Forwarded,
	"DROPPED":    flow.Dropped,
	"AUDIT":      flow.Audit,
	"REDIRECTED": flow.Redirected,
}

// TrafficDirection maps Hubble JSON traffic_direction strings.
var directionMap = map[string]flow.Direction{
	"INGRESS":  flow.Ingress,
	"EGRESS":   flow.Egress,
	"INTERNAL": flow.Internal,
}

// Protocol maps Hubble JSON l4.protocol strings.
var protoMap = map[string]flow.Protocol{
	"TCP":  flow.TCP,
	"UDP":  flow.UDP,
	"ICMP": flow.ICMP,
	"SCTP": flow.SCTP,
}

// hubbleFlow is the raw JSON structure for a Hubble flow record.
// Field tags match the Cilium Hubble --output json format.
type hubbleFlow struct {
	Time             string      `json:"time"`
	Verdict          string      `json:"verdict"`
	TrafficDirection string    `json:"traffic_direction"`
	IPVersion        string      `json:"ip_version"`
	IP               *hubbleIP   `json:"ip,omitempty"`
	L4               *hubbleLayer4 `json:"l4"`
	Source           *hubbleEndpoint  `json:"source"`
	Destination      *hubbleEndpoint  `json:"destination"`
	L7               *hubbleL7       `json:"l7"`
	Hints            *hubbleHints    `json:"hints,omitempty"`
	Bytes            uint64           `json:"bytes,omitempty"`
	Packets          uint64           `json:"packets,omitempty"`
	IsReply          bool             `json:"is_reply,omitempty"`
	Reply            bool             `json:"reply,omitempty"`
	DropReason       dropReasonJSON   `json:"drop_reason,omitempty"`
	PolicyNames      []string         `json:"policy_names,omitempty"`
}

// hubbleIP is the top-level IP object in a Hubble flow.
type hubbleIP struct {
	Source string `json:"source"`
	Dest   string `json:"destination"`
}

// hubbleLayer4 holds Layer 4 transport details.
type hubbleLayer4 struct {
	Protocol  string                  `json:"protocol"`
	TCP       *hubbleLayer4TCPUDP     `json:"tcp,omitempty"`
	UDP       *hubbleLayer4TCPUDP     `json:"udp,omitempty"`
	ICMP      *hubbleLayer4ICMP       `json:"icmp,omitempty"`
	TCPProto  *hubbleLayer4TCPUDPProto `json:"TCP,omitempty"`
	UDPProto  *hubbleLayer4TCPUDPProto `json:"UDP,omitempty"`
}

// hubbleLayer4TCPUDP holds port/protocol info for TCP and UDP.
type hubbleLayer4TCPUDP struct {
	Source struct {
		Port uint16 `json:"port"`
	} `json:"source"`
	Dest struct {
		Port uint16 `json:"port"`
	} `json:"destination"`
}

// hubbleLayer4TCPUDPProto holds port info in the protojson (flat) shape:
//   {"source_port": 48312, "destination_port": 8080}
// emitted by HubbleGRPCClient via protojson.MarshalOptions{UseProtoNames: true}.
type hubbleLayer4TCPUDPProto struct {
	SourcePort uint16 `json:"source_port"`
	DestPort   uint16 `json:"destination_port"`
}

// hubbleLayer4ICMP holds type/code for ICMP.
type hubbleLayer4ICMP struct {
	Type int32 `json:"type"`
	Code int32 `json:"code"`
}

// hubbleEndpoint describes a Hubble endpoint.
type hubbleEndpoint struct {
	Namespace  string   `json:"namespace"`
	PodName    string   `json:"pod_name"`
	PodNsp     string   `json:"pod_namespace"`
	Service    string   `json:"service"`
	Labels     []string `json:"labels"`
	IPs        []string `json:"IPs"`
	Name       string   `json:"name"`
	Workloads  []struct {
		Port uint16 `json:"port"`
	} `json:"workloads,omitempty"`
}

// hubbleL7 holds Layer 7 inspection data as defined in flow.proto.
type hubbleL7 struct {
	DNS  *hubbleL7DNS  `json:"dns,omitempty"`
	HTTP *hubbleL7HTTP `json:"http,omitempty"`
	TLS  *hubbleTLS    `json:"tls,omitempty"`
}

// hubbleL7DNS holds DNS query data.
type hubbleL7DNS struct {
	Query string `json:"query"`
}

// hubbleL7HTTP holds HTTP request data.
type hubbleL7HTTP struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Host   string `json:"host"`
}

// hubbleTLS holds TLS inspection data.
type hubbleTLS struct {
	SNI string `json:"sni"`
}

// hubbleHints holds legacy-style L7 hints embedded in a top-level "hints"
// object. This captures the format used in some Hubble JSON outputs where
// DNS/HTTP/TLS hints arrive under hints.dns, hints.http, or hints.tls
// rather than under l7.
type hubbleHints struct {
	DNS  *hintsDNS   `json:"dns,omitempty"`
	HTTP *hintsHTTP  `json:"http,omitempty"`
	TLS  *hintsTLS   `json:"tls,omitempty"`
}

// dropReasonJSON accepts both a string and a number from the Hubble
// `drop_reason` field. Some Hubble versions emit it as a quoted
// reason string, others emit a numeric drop reason code.
type dropReasonJSON struct {
	String string
}

func (d *dropReasonJSON) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	if data[0] == '"' {
		d.String = string(data[1 : len(data)-1])
		return nil
	}
	d.String = string(data)
	return nil
}

type hintsDNS struct {
	Query string `json:"query"`
}

type hintsHTTP struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Host   string `json:"host"`
}

type hintsTLS struct {
	SNI string `json:"sni"`
}

// Parser parses newline-delimited Hubble JSON flow records.
type Parser struct{}

// Default returns SourceHubble as the canonical parser identifier.
func (p *Parser) Default() parser.Source {
	return SourceHubble
}

// Source returns the parser's identifier.
func (p *Parser) Source() parser.Source {
	return SourceHubble
}

// Parse reads a stream of newline-delimited Hubble JSON records and emits
// mapped [flow.Flow] values via the emit callback. It returns a *parser.FormatError
// on the first parse failure (invalid JSON, missing source, missing verdict).
func (p *Parser) Parse(r io.Reader, emit func(flow.Flow) error) error {
	// Use bufio.Reader.ReadString (not bufio.Scanner) because real Hubble
	// protojson lines from HubbleGRPCClient routinely exceed any fixed
	// Scanner buffer size (1 MB, 8 MB, even more) due to long label lists
	// and many L7 fields. ReadString grows the underlying buffer as needed
	// and only stops at '\n' or EOF.
	br := bufio.NewReader(r)

	lineNum := 0
	for {
		line, readErr := br.ReadString('\n')
		if len(line) > 0 {
			lineNum++
			// Strip trailing '\n' (and any trailing '\r' for safety).
			if line[len(line)-1] == '\n' {
				line = line[:len(line)-1]
			}
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}

			// Skip blank lines.
			if len(line) == 0 {
				if readErr != nil {
					break
				}
				continue
			}

			f, err := p.parseLine(line)
			if err != nil {
				return &parser.FormatError{
					Source:  SourceHubble,
					Message: fmt.Sprintf("line %d: %v", lineNum, err),
				}
			}

			if err := emit(f); err != nil {
				return err
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return nil
			}
			return readErr
		}
	}
	return nil
}

// parseLine decodes a single JSON object into a [flow.Flow].
func (p *Parser) parseLine(line string) (flow.Flow, error) {
	var raw hubbleFlow
	// Use json.Decoder so trailing data after the first JSON object
	// (e.g. concatenated flows from a batched gRPC stream) is silently
	// ignored instead of returning "invalid character ... after top-level value".
	if err := json.NewDecoder(strings.NewReader(line)).Decode(&raw); err != nil {
		return flow.Flow{}, fmt.Errorf("%s", err.Error())
	}

	f, err := mapFlow(&raw)
	if err != nil {
		return flow.Flow{}, err
	}
	return f, nil
}

// mapFlow maps a raw hubbleFlow into a [flow.Flow].
func mapFlow(raw *hubbleFlow) (flow.Flow, error) {
	var f flow.Flow

	// --- Time ---
	if raw.Time != "" {
		t, err := time.Parse(time.RFC3339Nano, raw.Time)
		if err != nil {
			return flow.Flow{}, fmt.Errorf("parse time: %w", err)
		}
		f.Time = t
	} else {
		return flow.Flow{}, fmt.Errorf("missing required field time")
	}

	// --- Verdict ---
	if raw.Verdict == "" {
		return flow.Flow{}, fmt.Errorf("missing required field verdict")
	}
	v, ok := verdictMap[raw.Verdict]
	if !ok {
		return flow.Flow{}, fmt.Errorf("unknown verdict: %q", raw.Verdict)
	}
	f.Verdict = v

	// --- Direction ---
	if raw.TrafficDirection != "" {
		d, ok := directionMap[raw.TrafficDirection]
		if !ok {
			return flow.Flow{}, fmt.Errorf("unknown traffic_direction: %q", raw.TrafficDirection)
		}
		f.Direction = d
	}

	// --- Endpoint helpers ---
	if raw.Source == nil {
		return flow.Flow{}, fmt.Errorf("missing required field source")
	}
	if raw.Destination == nil {
		return flow.Flow{}, fmt.Errorf("missing required field destination")
	}

	f.Source = parseEndpoint(raw.Source)
	f.Destination = parseEndpoint(raw.Destination)

	// Protojson shape: top-level IP.source / IP.destination carry endpoint IPs
	// (the per-endpoint `IPs` array is absent in protojson emitted by HubbleGRPCClient).
	if raw.IP != nil {
		if raw.IP.Source != "" && f.Source.IP == "" {
			f.Source.IP = raw.IP.Source
		}
		if raw.IP.Dest != "" && f.Destination.IP == "" {
			f.Destination.IP = raw.IP.Dest
		}
	}

	f.SourceLabels = f.Source.Labels

	// --- Layer 4 ---
	if raw.L4 != nil {
		f.Layer4 = parseLayer4(raw.L4)
	}

	// --- L7 hints ---
	f.L7 = parseL7(raw.L7, raw.Hints)

	// --- Bytes ---
	if raw.Bytes > 0 {
		f.Bytes = raw.Bytes
	}

	// --- Packets ---
	if raw.Packets > 0 {
		f.Packets = raw.Packets
	}

	// --- IsReply ---
	f.IsReply = raw.IsReply || raw.Reply

	// --- DropReason ---
	if raw.DropReason.String != "" {
		f.DropReason = raw.DropReason.String
	}

	// --- PolicyNames ---
	if len(raw.PolicyNames) > 0 {
		f.PolicyName = raw.PolicyNames[0]
	}

	return f, nil
}

// parseEndpoint maps a [hubbleEndpoint] to a [flow.Endpoint].
func parseEndpoint(raw *hubbleEndpoint) flow.Endpoint {
	var ep flow.Endpoint

	ep.Namespace = raw.Namespace
	if raw.PodName != "" {
		ep.PodName = raw.PodName
	}
	// pod_namespace is also valid and may differ in some Hubble versions.
	if ep.Namespace == "" && raw.PodNsp != "" {
		ep.Namespace = raw.PodNsp
	}
	if len(raw.IPs) > 0 {
		ep.IP = raw.IPs[0]
	}
	if len(raw.Labels) > 0 {
		ep.Labels = parseLabels(raw.Labels)
	}

	return ep
}

// parseLabels splits array of "key=value" strings into a map.
func parseLabels(labels []string) map[string]string {
	m := make(map[string]string, len(labels))
	for _, l := range labels {
		idx := -1
		for i, c := range l {
			if c == '=' {
				idx = i
				break
			}
		}
		if idx <= 0 {
			continue // malformed: "key=value" must have at least "k=v"
		}
		m[l[:idx]] = l[idx+1:]
	}
	return m
}

// parseLayer4 maps a [hubbleLayer4] to [flow.Layer4].
func parseLayer4(raw *hubbleLayer4) flow.Layer4 {
	var l4 flow.Layer4

	// Protojson shape: oneof field name (TCP/UDP uppercase) is the protocol,
	// and the inner struct has flat source_port/destination_port fields.
	// Check this BEFORE the CLI shape so protojson takes precedence.
	if raw.TCPProto != nil {
		l4.Protocol = flow.TCP
		l4.SourcePort = raw.TCPProto.SourcePort
		l4.DestPort = raw.TCPProto.DestPort
		return l4
	}
	if raw.UDPProto != nil {
		l4.Protocol = flow.UDP
		l4.SourcePort = raw.UDPProto.SourcePort
		l4.DestPort = raw.UDPProto.DestPort
		return l4
	}

	if raw.Protocol != "" {
		l4.Protocol = protoMap[raw.Protocol]
		if l4.Protocol == "" {
			l4.Protocol = flow.Protocol(raw.Protocol)
		}
	}

	switch {
	case raw.TCP != nil:
		l4.SourcePort = raw.TCP.Source.Port
		l4.DestPort = raw.TCP.Dest.Port
	case raw.UDP != nil:
		l4.SourcePort = raw.UDP.Source.Port
		l4.DestPort = raw.UDP.Dest.Port
	case raw.ICMP != nil:
		l4.Protocol = flow.ICMP
		l4.SourcePort = uint16(raw.ICMP.Type)
		l4.DestPort = uint16(raw.ICMP.Code)
	}

	return l4
}

// parseL7 maps L7 hints from [hubbleL7] and [hubbleHints].
func parseL7(hl7 *hubbleL7, hints *hubbleHints) *flow.L7Hint {
	if hl7 == nil && hints == nil {
		return nil
	}

	// Prefer explicit l7 object (proto-defined).
	if hl7 != nil {
		if hl7.DNS != nil && hl7.DNS.Query != "" {
			return &flow.L7Hint{
				Type:  "dns",
				Query: hl7.DNS.Query,
			}
		}
		if hl7.HTTP != nil && (hl7.HTTP.Method != "" || hl7.HTTP.Path != "") {
			h := &flow.L7Hint{
				Type:   "http",
				Method: hl7.HTTP.Method,
				Path:   hl7.HTTP.Path,
			}
			if hl7.HTTP.Host != "" {
				h.Host = hl7.HTTP.Host
			}
			return h
		}
		if hl7.TLS != nil && hl7.TLS.SNI != "" {
			return &flow.L7Hint{
				Type: "tls",
				Host: hl7.TLS.SNI,
			}
		}
	}

	// Fall back to hints object.
	if hints != nil {
		if hints.DNS != nil && hints.DNS.Query != "" {
			return &flow.L7Hint{
				Type:  "dns",
				Query: hints.DNS.Query,
			}
		}
		if hints.HTTP != nil && (hints.HTTP.Method != "" || hints.HTTP.Path != "") {
			h := &flow.L7Hint{
				Type:   "http",
				Method: hints.HTTP.Method,
				Path:   hints.HTTP.Path,
			}
			if hints.HTTP.Host != "" {
				h.Host = hints.HTTP.Host
			}
			return h
		}
		if hints.TLS != nil && hints.TLS.SNI != "" {
			return &flow.L7Hint{
				Type: "tls",
				Host: hints.TLS.SNI,
			}
		}
	}

	return nil
}

// ensure Parser implements the interface.
var _ parser.Parser = (*Parser)(nil)

// Source is also provided via a global function for convenience.
func Source() parser.Source {
	return SourceHubble
}

func init() {
	parser.RegisterParser(SourceHubble, func() parser.Parser { return &Parser{} })
}

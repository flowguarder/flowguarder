package parser

import (
	"errors"
	"fmt"
	"io"

	"github.com/flowguarder/flowguarder/pkg/flow"
)

// Source identifies the origin of parsed flow data.
type Source int

const (
	// SourceHubble indicates data originates from Cilium Hubble.
	SourceHubble Source = iota
	// SourceCalico indicates data originates from Calico OSS aggregated flows.
	SourceCalico
	// SourceCalicoSyslog indicates data originates from Calico JSON-in-syslog lines.
	SourceCalicoSyslog
	// SourceGoldmane indicates data originates from Calico Goldmane gRPC API (FlowResult JSON).
	SourceGoldmane
	// SourceUnknown indicates an unrecognized flow source.
	SourceUnknown
	// SourceAuto indicates the source should use auto-detection based on data
	// heuristics at parse time.
	SourceAuto
)

// FormatError is a structured error returned by parsers when a specific record
// cannot be parsed. It carries the Source so callers can attribute failures
// to the correct input channel.
type FormatError struct {
	Source  Source
	Message string
}

func (e *FormatError) Error() string {
	return fmt.Sprintf("parser: %s format error: %s", e.sourceName(), e.Message)
}

func (e *FormatError) sourceName() string {
	switch e.Source {
	case SourceHubble:
		return "hubble"
	case SourceCalico:
		return "calico"
	case SourceCalicoSyslog:
		return "calico_syslog"
	case SourceGoldmane:
		return "goldmane"
	default:
		return "unknown"
	}
}

var (
	// ErrAmbiguous indicates that a flow record contained enough fields from
	// multiple source formats that auto-detection could not resolve a unique
	// parser confidently.
	ErrAmbiguous = errors.New("parser: ambiguous source format encountered")
	// ErrUnknown indicates that a source type is not recognized by the loader.
	ErrUnknown = errors.New("parser: unknown source type")
)

// Parser is the interface that all flow parsers must implement. A Parser
// reads structured flow records from an [io.Reader] and delivers them to the
// emit callback. Each emitted record is a fully populated [flow.Flow].
//
// Parsers SHOULD skip unparseable lines or records and call emit only for
// successfully parsed flows. On a parse error, the parser may choose to
// invoke emit with either nothing or skip the line, depending on its error
// policy. The emit callback returns an error to signal processing should stop.
type Parser interface {
	// Parse reads records from r, parsing each into a flow.Flow and passing it
	// to emit. Returns nil on success or a parser-level error (e.g.
	// *FormatError, ErrAmbiguous, ErrUnknown) otherwise.
	Parse(r io.Reader, emit func(flow.Flow) error) error
	// Source returns the parser's identifier.
	Source() Source
}

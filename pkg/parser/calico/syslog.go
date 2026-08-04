// Package calico provides a syslog-streaming parser for Calico aggregated
// flow-log records whose payload is JSON.  Each input line is an RFC 5424
// syslog message; the message body is a single JSON object.
//
// The parser strips the syslog header and reuses the core [parseLine]
// function so the canonical field mapping is exercised directly.
package calico

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/flowguarder/flowguarder/pkg/flow"
	"github.com/flowguarder/flowguarder/pkg/parser"
)

// syslogParserLogger logs warnings for malformed syslog lines.
var syslogParserLogger = log.New(&discardWriter{}, "", log.LstdFlags)

// SyslogParser implements [parser.Parser] for Calico JSON-in-syslog records.
type SyslogParser struct{}

// Source returns the source identifier for this parser.
func (p *SyslogParser) Source() parser.Source {
	return parser.SourceCalicoSyslog
}

// Parse reads syslog lines from r, extracts the JSON payload of each, maps
// it to a canonical [flow.Flow], and passes it to emit.  Un-parseable syslog
// headers or malformed JSON are reported as [parser.FormatError].
func (p *SyslogParser) Parse(r io.Reader, emit func(flow.Flow) error) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		jsonPart, err := extractJSONFromSyslog(line)
		if err != nil {
			syslogParserLogger.Printf("skipping syslog line (extract): %v", err)
			continue
		}

		f, err := parseLine(jsonPart)
		if err != nil {
			// parseLine already wraps in *FormatError with SourceCalico;
			// convert to SourceCalicoSyslog for proper attribution.
			if fe, ok := err.(*parser.FormatError); ok {
				fe.Source = parser.SourceCalicoSyslog
			}
			syslogParserLogger.Printf("skipping syslog line (parse): %v", err)
			continue
		}

		if err := emit(f); err != nil {
			return err
		}
	}

	return scanner.Err()
}

// extractJSONFromSyslog strips the RFC 5424 syslog header and returns the
// JSON message payload.
//
// RFC 5424 structure:
//
//	<priority>timestamp hostname appname[pid]: message
//
// The JSON message always starts with '{' right after the header separator.
func extractJSONFromSyslog(line string) (string, error) {
	// 1. Find closing '>' of the priority field.
	priEnd := strings.IndexByte(line, '>')
	if priEnd == -1 {
		return "", &parser.FormatError{
			Source:  parser.SourceCalicoSyslog,
			Message: "no priority field found (missing '>')",
		}
	}

	// 2. From after '>', find the first ': ' that separates header from message.
	//    Timestamps contain colons (e.g. 08:30:01) but they are not followed by
	//    a space, so the first ': ' is guaranteed to be the header separator.
	after := line[priEnd+1:]
	sep := strings.Index(after, ": ")
	if sep == -1 {
		return "", &parser.FormatError{
			Source:  parser.SourceCalicoSyslog,
			Message: "no header/message separator found",
		}
	}

	payload := strings.TrimSpace(after[sep+2:])
	if payload == "" {
		return "", &parser.FormatError{
			Source:  parser.SourceCalicoSyslog,
			Message: "empty syslog message",
		}
	}

	if !strings.HasPrefix(payload, "{") {
		return "", &parser.FormatError{
			Source:  parser.SourceCalicoSyslog,
			Message: fmt.Sprintf("message does not look like JSON (expected '{', got '%c')", payload[0]),
		}
	}

	return payload, nil
}

// init registers the SyslogParser for auto-detection via SelectParser.
func init() {
	parser.RegisterParser(parser.SourceCalicoSyslog, func() parser.Parser { return &SyslogParser{} })
}

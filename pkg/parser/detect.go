// Package parser provides flow-log parsing, source auto-detection, and the
// parser selection utility for the flowguarder CLI.
package parser

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// maxDetectBytes is the maximum number of bytes read for format detection.
const maxDetectBytes = 4096

// parserRegistry maps a Source to its concrete parser constructor.
// Registered by init() in subpackages (hubble, calico).
var parserRegistry = map[Source]func() Parser{}

// RegisterParser registers a parser constructor for a given Source.
// Called by subpackages in their init() to avoid import cycles.
func RegisterParser(src Source, fn func() Parser) {
	parserRegistry[src] = fn
}

// ---------------------------------------------------------------------------
// Auto-detection
// ---------------------------------------------------------------------------

// DetectFormat inspects the first 4096 bytes of r and tries to determine the
// flow-log format from the entire blob (first non-empty line for syslog, full
// blob for JSON probes):
//
//	- First non-empty line starting with '<' (syslog priority prefix) → SourceCalicoSyslog
//	- Blob containing a JSON field "verdict"                           → SourceHubble
//	- Blob containing "flow" AND "sourceName"                           → SourceGoldmane
//	- Blob containing a JSON field "action"                             → SourceCalico
//
// When no recognized probe is found the function returns a FormatError.
// Returns ErrAmbiguous also when the input is empty or contains no parsable line.
func DetectFormat(r io.Reader) (Source, error) {
	limited := &io.LimitedReader{R: r, N: maxDetectBytes}

	data, err := io.ReadAll(limited)
	if err != nil {
		return SourceUnknown, fmt.Errorf("reading for detection: %w", err)
	}

	blob := string(data)

	if len(strings.TrimSpace(blob)) == 0 {
		return SourceUnknown, fmt.Errorf("empty input: nothing to detect")
	}

	// Syslog: first non-empty line starts with '<'.
	// Use blob-level checks — either the whole blob starts with '<',
	// or a newline is immediately followed by '<'.
	if strings.HasPrefix(blob, "<") || strings.Contains(blob, "\n<") {
		return SourceCalicoSyslog, nil
	}

	// Check the first non-empty line for JSON keywords before falling
	// through to a full-blob scan.  This preserves the "first line wins"
	// behaviour for compact JSONL inputs while still catching keywords
	// that may sit on line 2+ in pretty-printed formats.
	lines := strings.Split(blob, "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.Contains(line, `"verdict"`) {
			return SourceHubble, nil
		}
		if strings.Contains(line, `"flow"`) && strings.Contains(line, `"sourceName"`) {
			return SourceGoldmane, nil
		}
		if strings.Contains(line, `"action"`) {
			return SourceCalico, nil
		}
		break // first non-empty line didn't match — fall through to full-blob scan
	}

	// Pretty-printed/multi-line JSON — keywords may not appear on the
	// first non-empty line, so scan the entire blob.
	if strings.Contains(blob, `"verdict"`) {
		return SourceHubble, nil
	}
	if strings.Contains(blob, `"flow"`) && strings.Contains(blob, `"sourceName"`) {
		return SourceGoldmane, nil
	}
	if strings.Contains(blob, `"action"`) {
		return SourceCalico, nil
	}

	return SourceUnknown, &FormatError{
		Source:  SourceUnknown,
		Message: "no recognized flow-log format detected",
	}
}

// DetectFormatFile opens the file at path, calls DetectFormat, and closes it.
func DetectFormatFile(path string) (Source, error) {
	f, err := os.Open(path)
	if err != nil {
		return SourceUnknown, fmt.Errorf("opening file %s: %w", path, err)
	}
	defer f.Close()

	src, err := DetectFormat(f)
	if err != nil {
		return SourceUnknown, fmt.Errorf("detecting format in %s: %w", path, err)
	}
	return src, nil
}

// fileMatch returns true if name looks like a JSON or log file we should probe.
func fileMatch(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".json") ||
		strings.HasSuffix(lower, ".jsonl") ||
		strings.HasSuffix(lower, ".json.gz") ||
		strings.HasSuffix(lower, ".log") ||
		strings.HasSuffix(lower, ".log.gz")
}

// DetectFormatDir scans the first file in dir matching *.json* or *.log* and
// delegates to DetectFormatFile.  Returns a FormatError when no suitable file
// is found in the directory.
func DetectFormatDir(dir string) (Source, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return SourceUnknown, fmt.Errorf("reading directory %s: %w", dir, err)
	}

	var matches []os.DirEntry
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.IsDir() {
			continue
		}
		if fileMatch(e.Name()) {
			matches = append(matches, e)
		}
	}

	if len(matches) == 0 {
		return SourceUnknown, &FormatError{
			Source:  SourceUnknown,
			Message: "no JSON/log files found in directory",
		}
	}

	// Sort by name so we have deterministic behaviour.
	for i := 0; i < len(matches); i++ {
		for j := i + 1; j < len(matches); j++ {
			if matches[i].Name() > matches[j].Name() {
				matches[i], matches[j] = matches[j], matches[i]
			}
		}
	}

	path := filepath.Join(dir, matches[0].Name())
	return DetectFormatFile(path)
}

// SelectParser resolves the effective source and returns the concrete parser.
//
// If override is SourceAuto the detected src is used; otherwise the explicit
// override takes priority and the detected src is discarded.
//
// The caller (e.g. CLI wiring in Task 28) passes SourceAuto when no
// --source CLI flag was provided, or one of SourceHubble / SourceCalico /
// SourceCalicoSyslog when the user forced a source type.
func SelectParser(src Source, override Source) (Parser, error) {
	actual := src
	if override != SourceAuto {
		actual = override
	}

	switch actual {
	case SourceHubble, SourceCalico, SourceCalicoSyslog, SourceGoldmane:
		if fn, ok := parserRegistry[actual]; ok {
			return fn(), nil
		}
	case SourceAuto:
		return nil, &FormatError{
			Source:  SourceAuto,
			Message: "auto-detect requires a reader; call DetectFormat first before SelectParser",
		}
	}

	return nil, &FormatError{
		Source:  actual,
		Message: fmt.Sprintf("no parser available for source %d", actual),
	}
}

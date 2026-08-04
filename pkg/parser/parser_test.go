package parser

import (
	"io"
	"testing"

	"github.com/flowguarder/flowguarder/pkg/flow"
)

// stubParser implements Parser solely for compile-time interface checking.
type stubParser struct{}

func (s *stubParser) Parse(r io.Reader, emit func(flow.Flow) error) error {
	return nil
}

func (s *stubParser) Source() Source {
	return SourceHubble
}

// Compile-time interface check: var _ Parser ensures *stubParser implements
// the Parser interface. This test will not compile if the interface changes.
var _ Parser = (*stubParser)(nil)

func TestCompileTimeParserInterface(t *testing.T) {
	_ = t
}

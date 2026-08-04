package ingest

import (
	"context"
	"io"
	"testing"

	"github.com/flowguarder/flowguarder/pkg/parser"
)

// stubSource implements Source solely for compile-time interface checking.
type stubSource struct{}

func (s *stubSource) Open(context.Context) (io.ReadCloser, error) { return io.NopCloser(nil), nil }
func (s *stubSource) Format() parser.Source                       { return parser.SourceHubble }

// Compile-time interface check: var _ Source ensures *stubSource implements
// the Source interface. This test will not compile if the interface changes.
var _ Source = (*stubSource)(nil)

func TestCompileTimeSourceInterface(t *testing.T) {
	// Purpose: verify compile-time compliance.
	// The var declaration above already performs the check at compile time.
	// This function is a no-op but makes the test file's purpose explicit.
	_ = t
}

package visualize

import (
	"strings"
	"testing"
)

// TestSelectLayoutMode covers the binding threshold matrix, manual overrides,
// and strict-lowercase validation. Arguments for auto cells are (nodes, edges).
func TestSelectLayoutMode(t *testing.T) {
	t.Parallel()

	autoCases := []struct {
		name  string
		nodes int
		edges int
		want  LayoutMode
	}{
		{"curved at inclusive bounds nodes=80 edges=100", 80, 100, ModeCurved},
		{"curved when nodes exceed straight bound", 81, 100, ModeCurved},
		{"curved when edges exceed straight bound", 80, 101, ModeCurved},
		{"curved mid-range", 50, 101, ModeCurved},
		{"curved at inclusive bounds nodes=180 edges=250", 180, 250, ModeCurved},
		{"orthogonal when nodes exceed curved bound", 181, 250, ModeOrthogonal},
		{"orthogonal when edges exceed curved bound", 180, 251, ModeOrthogonal},
		{"orthogonal when only node count is huge", 200, 50, ModeOrthogonal},
		{"curved for empty graph", 0, 0, ModeCurved},
		{"curved for single edge", 1, 1, ModeCurved},
	}

	for _, tc := range autoCases {
		tc := tc
		t.Run("auto/"+tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := SelectLayoutMode(tc.nodes, tc.edges, "")
			if err != nil {
				t.Fatalf("SelectLayoutMode(%d, %d, \"\") error: %v", tc.nodes, tc.edges, err)
			}
			if got != tc.want {
				t.Fatalf("SelectLayoutMode(%d, %d, \"\") = %q, want %q", tc.nodes, tc.edges, got, tc.want)
			}
		})
	}

	// "" must be exactly equivalent to "auto" — prove it on a spread of cells.
	for _, tc := range []autoCase{
		{80, 100, ModeCurved},
		{180, 250, ModeCurved},
		{200, 50, ModeOrthogonal},
	} {
		tc := tc
		t.Run("auto-explicit/auto keyword equals empty string", func(t *testing.T) {
			t.Parallel()
			got, err := SelectLayoutMode(tc.nodes, tc.edges, "auto")
			if err != nil {
				t.Fatalf("SelectLayoutMode(%d, %d, \"auto\") error: %v", tc.nodes, tc.edges, err)
			}
			if got != tc.want {
				t.Fatalf("SelectLayoutMode(%d, %d, \"auto\") = %q, want %q", tc.nodes, tc.edges, got, tc.want)
			}
		})
	}

	overrideCases := []struct {
		name   string
		manual string
		nodes  int
		edges  int
	}{
		{"manual straight wins at huge size", "straight", 500, 900},
		{"manual orthogonal wins at tiny size", "orthogonal", 0, 0},
		{"manual curved wins at tiny size", "curved", 0, 0},
	}
	for _, tc := range overrideCases {
		tc := tc
		t.Run("override/"+tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := SelectLayoutMode(tc.nodes, tc.edges, tc.manual)
			if err != nil {
				t.Fatalf("SelectLayoutMode(%d, %d, %q) error: %v", tc.nodes, tc.edges, tc.manual, err)
			}
			if got != LayoutMode(tc.manual) {
				t.Fatalf("SelectLayoutMode(%d, %d, %q) = %q, want %q", tc.nodes, tc.edges, tc.manual, got, tc.manual)
			}
		})
	}

	invalidCases := []string{"bogus", "Auto", "STRAIGHT", "auto "}
	for _, manual := range invalidCases {
		manual := manual
		t.Run("invalid/"+strings.ReplaceAll(manual, " ", "<space>"), func(t *testing.T) {
			t.Parallel()
			got, err := SelectLayoutMode(10, 10, manual)
			if err == nil {
				t.Fatalf("SelectLayoutMode(10, 10, %q) = %q, want error", manual, got)
			}
			const wantSubstr = "auto|straight|orthogonal|curved"
			if !strings.Contains(err.Error(), wantSubstr) {
				t.Fatalf("error %q does not mention allowed values %q", err.Error(), wantSubstr)
			}
		})
	}
}

// autoCase mirrors one row of the auto-selection table.
type autoCase struct {
	nodes int
	edges int
	want  LayoutMode
}

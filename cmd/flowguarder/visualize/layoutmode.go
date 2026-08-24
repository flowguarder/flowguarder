package visualize

import "fmt"

// LayoutMode selects the edge-drawing engine used by the HTML visualization.
type LayoutMode string

const (
	// ModeStraight draws edges as direct bezier lines between endpoints
	// (Cytoscape preset layout only — smallest payload).
	ModeStraight LayoutMode = "straight"

	// ModeOrthogonal positions nodes with ELK layered layout and routes
	// edges as right-angled (taxi) segments — best for large or dense
	// graphs where crossing minimization matters most.
	ModeOrthogonal LayoutMode = "orthogonal"

	// ModeCurved positions nodes with ELK and draws smooth arcs — a
	// middle ground that reduces crossings without the rigid layered look.
	ModeCurved LayoutMode = "curved"
)

// SelectLayoutMode resolves the effective [LayoutMode] for a graph with the
// given node/edge counts, honoring an explicit manual choice.
//
// Semantics (binding spec):
//   - manual "" is equivalent to "auto";
//   - validation is STRICT lowercase: accepted values are exactly "auto",
//     "straight", "orthogonal", "curved" — anything else (including case
//     variants such as "Auto" or values with surrounding whitespace) returns
//     an error listing all four allowed values;
//   - a valid explicit mode wins at ANY graph size;
//   - otherwise auto-selection uses INCLUSIVE thresholds: curved if
//     edges ≤ 250 AND nodes ≤ 180 (this also covers the former straight
//     tier); else orthogonal.
//
// Threshold rationale: per user product decision, curved arcs are preferred
// for ALL graphs up to the medium bound — they read better even on small
// graphs thanks to crossing reduction (the layout tournament showed curved
// arcs reduce edge crossings by up to ~70% versus straight lines); straight
// remains available explicitly for the minimal Cytoscape-only payload;
// large/dense graphs need ELK's layered orthogonal routing to stay readable.
// The function is pure: no I/O, no randomness,
// deterministic output for identical inputs.
func SelectLayoutMode(nodes, edges int, manual string) (LayoutMode, error) {
	switch manual {
	case "", "auto":
		// Auto selection below.
	case string(ModeStraight), string(ModeOrthogonal), string(ModeCurved):
		return LayoutMode(manual), nil
	default:
		return "", fmt.Errorf("invalid layout mode %q: allowed values are auto|straight|orthogonal|curved", manual)
	}

	if edges <= 250 && nodes <= 180 {
		return ModeCurved, nil
	}
	return ModeOrthogonal, nil
}

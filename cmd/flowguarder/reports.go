package main

import "fmt"

// validateReports checks that every name in reports is a known report type.
// Returns an error describing the invalid name(s).
func validateReports(reports []string) error {
	for _, r := range reports {
		if !validReports[r] {
			return fmt.Errorf("unknown report %q (valid: top-flows, uncovered, coverage, egress-world, drops, anomalies)", r)
		}
	}
	return nil
}

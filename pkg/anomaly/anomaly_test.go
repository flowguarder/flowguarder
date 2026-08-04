package anomaly

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSeverityByCount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		base   Severity
		count  uint64
		expect Severity
	}{
		{
			name:   "base high, count 1 -> medium",
			base:   SeverityHigh,
			count:  1,
			expect: SeverityMedium,
		},
		{
			name:   "base medium, count 1 -> low",
			base:   SeverityMedium,
			count:  1,
			expect: SeverityLow,
		},
		{
			name:   "base low, count 1 -> low (floor)",
			base:   SeverityLow,
			count:  1,
			expect: SeverityLow,
		},
		{
			name:   "base low, count 100 -> medium",
			base:   SeverityLow,
			count:  100,
			expect: SeverityMedium,
		},
		{
			name:   "base medium, count 100 -> high",
			base:   SeverityMedium,
			count:  100,
			expect: SeverityHigh,
		},
		{
			name:   "base high, count 100 -> high (cap)",
			base:   SeverityHigh,
			count:  100,
			expect: SeverityHigh,
		},
		{
			name:   "base medium, count 50 -> medium",
			base:   SeverityMedium,
			count:  50,
			expect: SeverityMedium,
		},
		{
			name:   "base high, count 50 -> high",
			base:   SeverityHigh,
			count:  50,
			expect: SeverityHigh,
		},
		{
			name:   "base info, count 1 -> info",
			base:   SeverityInfo,
			count:  1,
			expect: SeverityInfo,
		},
		{
			name:   "base info, count 100 -> medium",
			base:   SeverityInfo,
			count:  100,
			expect: SeverityMedium,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := severityByCount(tt.base, tt.count)
			require.Equal(t, tt.expect, got)
		})
	}
}

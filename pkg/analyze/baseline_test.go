package analyze

import (
	"math"
	"testing"
	"time"
)

func TestComputeBaseline(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Hour)

	tests := []struct {
		name        string
		patterns    []Pattern
		expectCount int
		expectKeys  []string
	}{
		{
			name:        "empty",
			patterns:    nil,
			expectCount: 0,
		},
		{
			name: "single pattern",
			patterns: []Pattern{
				{Key: "a -> b:80/TCP", Port: 80, Protocol: "TCP", Count: 100, FirstSeen: now},
			},
			expectCount: 1,
			expectKeys:  []string{"a -> b:80/TCP"},
		},
		{
			name: "multiple patterns merge same key",
			patterns: []Pattern{
				{Key: "a -> b:80/TCP", Port: 80, Protocol: "TCP", Count: 60, FirstSeen: now},
				{Key: "a -> b:80/TCP", Port: 80, Protocol: "TCP", Count: 40, FirstSeen: now.Add(time.Hour)},
				{Key: "c -> d:443/TCP", Port: 443, Protocol: "TCP", Count: 50, FirstSeen: now},
			},
			expectCount: 2,
			expectKeys:  []string{"a -> b:80/TCP", "c -> d:443/TCP"},
		},
		{
			name: "multiple hour buckets",
			patterns: []Pattern{
				{Key: "x -> y:22/TCP", Port: 22, Protocol: "TCP", Count: 10, FirstSeen: now},
				{Key: "x -> y:22/TCP", Port: 22, Protocol: "TCP", Count: 30, FirstSeen: now.Add(2 * time.Hour)},
				{Key: "x -> y:22/TCP", Port: 22, Protocol: "TCP", Count: 20, FirstSeen: now.Add(4 * time.Hour)},
			},
			expectCount: 1,
			expectKeys:  []string{"x -> y:22/TCP"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			baselines := ComputeBaseline(tt.patterns)

			if len(baselines) != tt.expectCount {
				t.Errorf("got %d baselines, want %d", len(baselines), tt.expectCount)
			}

			if tt.expectCount > 0 {
				gotKeys := make([]string, len(baselines))
				for i, b := range baselines {
					gotKeys[i] = b.PatternKey
				}
				if len(tt.expectKeys) > 0 {
					for i, wantKey := range tt.expectKeys {
						if i >= len(gotKeys) {
							t.Errorf("missing key: %s", wantKey)
							continue
						}
						if gotKeys[i] != wantKey {
							t.Errorf("baseline[%d] key = %q, want %q", i, gotKeys[i], wantKey)
						}
					}
				}
			}
		})
	}
}

func TestComputeBaseline_MeanStdDev(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Hour)
	patterns := []Pattern{
		{Key: "x -> y:22/TCP", Port: 22, Protocol: "TCP", Count: 10, FirstSeen: now},
		{Key: "x -> y:22/TCP", Port: 22, Protocol: "TCP", Count: 30, FirstSeen: now.Add(2 * time.Hour)},
		{Key: "x -> y:22/TCP", Port: 22, Protocol: "TCP", Count: 20, FirstSeen: now.Add(4 * time.Hour)},
	}

	baselines := ComputeBaseline(patterns)
	if len(baselines) != 1 {
		t.Fatalf("expected 1 baseline, got %d", len(baselines))
	}

	b := baselines[0]

	// Buckets: hours 0, 2, 4 → counts [10, 30, 20]
	// Mean = 60/3 = 20
	if b.MeanPerHour != 20 {
		t.Errorf("MeanPerHour = %v, want 20", b.MeanPerHour)
	}

	// StdDev (population) = sqrt(((10-20)^2 + (30-20)^2 + (20-20)^2) / 3)
	// = sqrt((100+100+0)/3) = sqrt(200/3) ≈ 8.16
	wantStdDev := math.Sqrt(200.0 / 3.0)
	if b.StdDev != wantStdDev {
		t.Errorf("StdDev = %v, want %v", b.StdDev, wantStdDev)
	}

	// TotalCount should be sum of all individual counts
	if b.TotalCount != 60 {
		t.Errorf("TotalCount = %v, want 60", b.TotalCount)
	}
}

func TestComputeBaseline_BucketsOrdered(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Hour)
	// Supply patterns out of order to test chronological bucket ordering.
	patterns := []Pattern{
		{Key: "a -> b:80/TCP", Port: 80, Protocol: "TCP", Count: 50, FirstSeen: now.Add(2 * time.Hour)},
		{Key: "a -> b:80/TCP", Port: 80, Protocol: "TCP", Count: 10, FirstSeen: now},
		{Key: "a -> b:80/TCP", Port: 80, Protocol: "TCP", Count: 30, FirstSeen: now.Add(4 * time.Hour)},
	}

	baselines := ComputeBaseline(patterns)
	if len(baselines) != 1 {
		t.Fatalf("expected 1 baseline, got %d", len(baselines))
	}

	b := baselines[0]
	if len(b.HourlyBuckets) != 3 {
		t.Fatalf("expected 3 buckets, got %d", len(b.HourlyBuckets))
	}

	// Buckets should be in chronological order: hours 0, 2, 4.
	expectedOrder := []uint64{10, 50, 30}
	for i, want := range expectedOrder {
		if b.HourlyBuckets[i].Count != want {
			t.Errorf("bucket[%d] Count = %d, want %d", i, b.HourlyBuckets[i].Count, want)
		}
	}
}

func TestBaselineFrequency(t *testing.T) {
	t.Parallel()

	b := Baseline{PatternKey: "a -> b:80/TCP", MeanPerHour: 42.5}
	got := BaselineFrequency(b)
	if got != 42.5 {
		t.Errorf("BaselineFrequency = %v, want 42.5", got)
	}
}

func TestIsRare(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		count     uint64
		meanPerH  float64
		threshold float64
		want      bool
	}{
		{
			name:      "normal traffic",
			count:     100,
			meanPerH:  50,
			threshold: 2.0,
			want:      false, // 100 >= 2*50
		},
		{
			name:      "rare traffic",
			count:     10,
			meanPerH:  50,
			threshold: 2.0,
			want:      true, // 10 < 2*50
		},
		{
			name:      "zero mean returns false",
			count:     1,
			meanPerH:  0,
			threshold: 2.0,
			want:      false,
		},
		{
			name:      "exactly at threshold",
			count:     100,
			meanPerH:  50,
			threshold: 2.0,
			want:      false, // 100 >= 2*50
		},
		{
			name:      "just below threshold",
			count:     99,
			meanPerH:  50,
			threshold: 2.0,
			want:      true, // 99 < 2*50
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b := Baseline{PatternKey: "x", MeanPerHour: tt.meanPerH}
			got := IsRare(tt.count, b, tt.threshold)
			if got != tt.want {
				t.Errorf("IsRare(%d, baseline{m=%.1f}, %.1f) = %v, want %v",
					tt.count, tt.meanPerH, tt.threshold, got, tt.want)
			}
		})
	}
}

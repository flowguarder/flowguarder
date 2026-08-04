package analyze

import (
	"math"
	"sort"
	"time"
)

// HourBucket represents traffic volume within a single hour window.
type HourBucket struct {
	Start time.Time
	Count uint64
}

// Baseline captures the time-distribution statistics for a single pattern.
type Baseline struct {
	PatternKey  string
	TotalCount  uint64
	HourlyBuckets []HourBucket
	MeanPerHour float64
	StdDev      float64
}

// ComputeBaseline builds a time-distribution baseline for every pattern.
//
// Patterns are first sorted by FirstSeen so buckets are emitted in chronological
// order.  Each flow-timestamp falls into the UTC-hour bucket matching its
// FirstSeen.  All matching patterns contribute their Count to that bucket.
// Mean and standard-deviation are computed from the hourly bucket counts.
func ComputeBaseline(patterns []Pattern) []Baseline {
	if len(patterns) == 0 {
		return nil
	}

	// Sort by FirstSeen to emit buckets chronologically.
	sorted := make([]Pattern, len(patterns))
	copy(sorted, patterns)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].FirstSeen.Before(sorted[j].FirstSeen)
	})

	// Group patterns by canonical key.
	keyGroups := make(map[string][]Pattern)
	for _, p := range sorted {
		keyGroups[p.Key] = append(keyGroups[p.Key], p)
	}

	// Collect unique keys in a deterministic order.
	keys := make([]string, 0, len(keyGroups))
	for k := range keyGroups {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	result := make([]Baseline, 0, len(keys))

	for _, key := range keys {
		group := keyGroups[key]

		// Each pattern contributes its Count to the hour bucket of its FirstSeen.
		buckets := make(map[int64]*HourBucket)
		bucketOrder := make([]int64, 0)
		var totalCount uint64

		for _, p := range group {
			totalCount += p.Count
			h := p.FirstSeen.Truncate(time.Hour).Unix()

			if _, ok := buckets[h]; !ok {
				buckets[h] = &HourBucket{Start: time.Unix(h, 0).UTC()}
				bucketOrder = append(bucketOrder, h)
			}
			buckets[h].Count += p.Count
		}

		sort.SliceStable(bucketOrder, func(i, j int) bool {
			return bucketOrder[i] < bucketOrder[j]
		})

		hourlyBuckets := make([]HourBucket, 0, len(bucketOrder))
		for _, h := range bucketOrder {
			hourlyBuckets = append(hourlyBuckets, *buckets[h])
		}

		baseline := Baseline{
			PatternKey:    key,
			TotalCount:    totalCount,
			HourlyBuckets: hourlyBuckets,
		}

		counts := make([]float64, 0, len(hourlyBuckets))
		for _, b := range hourlyBuckets {
			counts = append(counts, float64(b.Count))
		}

		if len(counts) > 0 {
			baseline.MeanPerHour = mean(counts)
			if len(counts) > 1 {
				baseline.StdDev = stddev(counts)
			}
		}

		result = append(result, baseline)
	}

	return result
}

// mean returns the arithmetic mean of the supplied values.
func mean(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals))
}

// stddev returns the population standard deviation of the supplied values.
func stddev(vals []float64) float64 {
	if len(vals) <= 1 {
		return 0
	}
	m := mean(vals)
	var sumSq float64
	for _, v := range vals {
		d := v - m
		sumSq += d * d
	}
	return math.Sqrt(sumSq / float64(len(vals)))
}

// BaselineFrequency returns a pattern's MeanPerHour.
func BaselineFrequency(b Baseline) float64 {
	return b.MeanPerHour
}

// IsRare checks whether an observed count is below the given threshold multiple of the baseline mean.
//
// Returns true when count < threshold * MeanPerHour.
func IsRare(count uint64, baseline Baseline, threshold float64) bool {
	if baseline.MeanPerHour == 0 {
		return false
	}
	return float64(count) < threshold*baseline.MeanPerHour
}

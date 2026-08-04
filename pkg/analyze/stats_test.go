package analyze

import (
	"testing"
	"time"

	"github.com/flowguarder/flowguarder/pkg/flow"
	"github.com/stretchr/testify/assert"
)

func TestPatternKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		src    string
		dst    string
		port   string
		proto  string
		expect string
	}{
		{
			name:   "standard case",
			src:    "default/frontend-abc12",
			dst:    "production/backend-xyz99",
			port:   "8080",
			proto:  "TCP",
			expect: "default/frontend-abc12 -> production/backend-xyz99:8080/TCP",
		},
		{
			name:   "udp protocol",
			src:    "default/alpha",
			dst:    "default/beta",
			port:   "53",
			proto:  "UDP",
			expect: "default/alpha -> default/beta:53/UDP",
		},
		{
			name:   "empty port",
			src:    "ns/app1",
			dst:    "ns/app2",
			port:   "",
			proto:  "ICMP",
			expect: "ns/app1 -> ns/app2:/ICMP",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := patternKey(tt.src, tt.dst, tt.port, tt.proto)
			assert.Equal(t, tt.expect, got)
		})
	}
}

func TestComputePatterns(t *testing.T) {
	t.Parallel()

	baseTime := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)

	tests := []struct {
		name         string
		flows        []flow.Flow
		workloads    Workloads
		wantLen      int
		wantKeys     []string
		wantCounts   []uint64
		wantBytes    []uint64
	}{
		{
			name:      "zero flows returns empty non-nil slice",
			flows:     nil,
			workloads: Workloads{},
			wantLen:   0,
		},
		{
			name: "empty flows slice returns empty non-nil slice",
			flows: []flow.Flow{},
			wantLen: 0,
		},
		{
			name: "two same pattern + one different",
			flows: []flow.Flow{
				{
					Time:      baseTime.Add(0),
					Direction: flow.Ingress,
					Source:    flow.Endpoint{Namespace: "production", PodName: "frontend-aaa", Labels: map[string]string{"app": "frontend"}},
					Destination: flow.Endpoint{Namespace: "production", PodName: "backend-bbb", Labels: map[string]string{"app": "backend"}},
					Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
					Bytes:     1000,
				},
				{
					Time:      baseTime.Add(1 * time.Minute),
					Direction: flow.Ingress,
					Source:    flow.Endpoint{Namespace: "production", PodName: "frontend-aaa", Labels: map[string]string{"app": "frontend"}},
					Destination: flow.Endpoint{Namespace: "production", PodName: "backend-bbb", Labels: map[string]string{"app": "backend"}},
					Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
					Bytes:     2000,
				},
				{
					Time:      baseTime.Add(2 * time.Minute),
					Direction: flow.Egress,
					Source:    flow.Endpoint{Namespace: "staging", PodName: "test-runner-ccc", Labels: map[string]string{"app": "test-runner"}},
					Destination: flow.Endpoint{Namespace: "production", PodName: "backend-bbb", Labels: map[string]string{"app": "backend"}},
					Layer4:    flow.Layer4{DestPort: 443, Protocol: flow.TCP},
					Bytes:     500,
				},
			},
			workloads: Workloads{},
			wantLen:   2,
			wantKeys: []string{
				"production/frontend -> production/backend:8080/TCP",
				"staging/test-runner -> production/backend:443/TCP",
			},
			wantCounts: []uint64{2, 1},
			wantBytes:  []uint64{3000, 500},
		},
		{
			name: "single flow produces one pattern",
			flows: []flow.Flow{
				{
					Time:      baseTime,
					Direction: flow.Egress,
					Source:    flow.Endpoint{Namespace: "default", PodName: "worker-111", Labels: map[string]string{"app": "worker"}},
					Destination: flow.Endpoint{Namespace: "default", PodName: "db-222", Labels: map[string]string{"app": "postgres"}},
					Layer4:    flow.Layer4{DestPort: 5432, Protocol: flow.TCP},
					Bytes:     100,
				},
			},
			workloads: Workloads{},
			wantLen:   1,
			wantKeys: []string{
				"default/worker -> default/postgres:5432/TCP",
			},
			wantCounts: []uint64{1},
			wantBytes:  []uint64{100},
		},
		{
			name: "zero bytes flow",
			flows: []flow.Flow{
				{
					Time:      baseTime,
					Direction: flow.Internal,
					Source:    flow.Endpoint{Namespace: "default", PodName: "a-1", Labels: map[string]string{"app": "alpha"}},
					Destination: flow.Endpoint{Namespace: "default", PodName: "b-2", Labels: map[string]string{"app": "beta"}},
					Layer4:    flow.Layer4{DestPort: 9090, Protocol: flow.UDP},
				},
			},
			workloads: Workloads{},
			wantLen:   1,
			wantKeys: []string{
				"default/alpha -> default/beta:9090/UDP",
			},
			wantCounts: []uint64{1},
			wantBytes:  []uint64{0},
		},
		{
			name: "same pattern different timestamps — first/last seen",
			flows: []flow.Flow{
				{
					Time:      baseTime.Add(5 * time.Minute),
					Direction: flow.Ingress,
					Source:    flow.Endpoint{Namespace: "default", PodName: "svc-a-1", Labels: map[string]string{"app": "sava"}},
					Destination: flow.Endpoint{Namespace: "default", PodName: "svc-b-1", Labels: map[string]string{"app": "svbb"}},
					Layer4:    flow.Layer4{DestPort: 80, Protocol: flow.TCP},
				},
				{
					Time:      baseTime,
					Direction: flow.Ingress,
					Source:    flow.Endpoint{Namespace: "default", PodName: "svc-a-1", Labels: map[string]string{"app": "sava"}},
					Destination: flow.Endpoint{Namespace: "default", PodName: "svc-b-1", Labels: map[string]string{"app": "svbb"}},
					Layer4:    flow.Layer4{DestPort: 80, Protocol: flow.TCP},
				},
				{
					Time:      baseTime.Add(10 * time.Minute),
					Direction: flow.Ingress,
					Source:    flow.Endpoint{Namespace: "default", PodName: "svc-a-1", Labels: map[string]string{"app": "sava"}},
					Destination: flow.Endpoint{Namespace: "default", PodName: "svc-b-1", Labels: map[string]string{"app": "svbb"}},
					Layer4:    flow.Layer4{DestPort: 80, Protocol: flow.TCP},
				},
			},
			workloads: Workloads{},
			wantLen:   1,
			wantKeys: []string{
				"default/sava -> default/svbb:80/TCP",
			},
			wantCounts: []uint64{3},
			wantBytes:  []uint64{0},
		},
		{
			name: "deterministic key order with many patterns",
			flows: []flow.Flow{
				{
					Time:      baseTime,
					Direction: flow.Ingress,
					Source:    flow.Endpoint{Namespace: "z", PodName: "z-1", Labels: map[string]string{"app": "z"}},
					Destination: flow.Endpoint{Namespace: "a", PodName: "a-1", Labels: map[string]string{"app": "a"}},
					Layer4:    flow.Layer4{DestPort: 1111, Protocol: flow.TCP},
				},
				{
					Time:      baseTime,
					Direction: flow.Ingress,
					Source:    flow.Endpoint{Namespace: "a", PodName: "b-2", Labels: map[string]string{"app": "b"}},
					Destination: flow.Endpoint{Namespace: "m", PodName: "c-3", Labels: map[string]string{"app": "c"}},
					Layer4:    flow.Layer4{DestPort: 2222, Protocol: flow.UDP},
				},
				{
					Time:      baseTime,
					Direction: flow.Egress,
					Source:    flow.Endpoint{Namespace: "m", PodName: "d-4", Labels: map[string]string{"app": "d"}},
					Destination: flow.Endpoint{Namespace: "a", PodName: "e-5", Labels: map[string]string{"app": "e"}},
					Layer4:    flow.Layer4{DestPort: 3333, Protocol: flow.TCP},
				},
			},
			workloads: Workloads{},
			wantLen:   3,
			wantKeys: []string{
				"a/b -> m/c:2222/UDP",
				"m/d -> a/e:3333/TCP",
				"z/z -> a/a:1111/TCP",
			},
			wantCounts: []uint64{1, 1, 1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ComputePatterns(tt.flows, tt.workloads)

			assert.Equal(t, tt.wantLen, len(got), "expected %d patterns, got %d", tt.wantLen, len(got))

			if tt.wantLen == 0 {
				assert.NotNil(t, got, "expected non-nil empty slice")
				return
			}

			for i, wantKey := range tt.wantKeys {
				assert.Equal(t, wantKey, got[i].Key, "pattern %d key mismatch", i)
			}

			for i, wantCount := range tt.wantCounts {
				assert.Equal(t, wantCount, got[i].Count, "pattern %d count mismatch", i)
			}

			for i, wantBytes := range tt.wantBytes {
				assert.Equal(t, wantBytes, got[i].Bytes, "pattern %d bytes mismatch", i)
			}

			// Verify deterministic order: keys must be sorted
			for i := 1; i < len(got); i++ {
				assert.Less(t, got[i-1].Key, got[i].Key, "keys not sorted at index %d", i)
			}

			// Verify FirstSeen <= LastSeen
			for _, p := range got {
				assert.True(t, !p.FirstSeen.After(p.LastSeen), "FirstSeen must be <= LastSeen")
			}
		})
	}
}

func TestComputePatterns_FirstLastSeen(t *testing.T) {
	t.Parallel()
	baseTime := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	flows := []flow.Flow{
		{
			Time:      baseTime.Add(30 * time.Minute),
			Direction: flow.Ingress,
			Source:    flow.Endpoint{Namespace: "default", PodName: "a-1", Labels: map[string]string{"app": "alpha"}},
			Destination: flow.Endpoint{Namespace: "default", PodName: "b-2", Labels: map[string]string{"app": "beta"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
		},
		{
			Time:      baseTime,
			Direction: flow.Ingress,
			Source:    flow.Endpoint{Namespace: "default", PodName: "a-1", Labels: map[string]string{"app": "alpha"}},
			Destination: flow.Endpoint{Namespace: "default", PodName: "b-2", Labels: map[string]string{"app": "beta"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
		},
		{
			Time:      baseTime.Add(1 * time.Hour),
			Direction: flow.Ingress,
			Source:    flow.Endpoint{Namespace: "default", PodName: "a-1", Labels: map[string]string{"app": "alpha"}},
			Destination: flow.Endpoint{Namespace: "default", PodName: "b-2", Labels: map[string]string{"app": "beta"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
		},
	}

	got := ComputePatterns(flows, Workloads{})
	assert.Equal(t, 1, len(got))
	assert.Equal(t, baseTime, got[0].FirstSeen)
	assert.Equal(t, baseTime.Add(1*time.Hour), got[0].LastSeen)
}

func TestComputePatterns_ProtoFallback(t *testing.T) {
	t.Parallel()
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Flow with empty protocol — should default to "UNKNOWN"
	flows := []flow.Flow{
		{
			Time:      baseTime,
			Direction: flow.Ingress,
			Source:    flow.Endpoint{Namespace: "ns", PodName: "app-1", Labels: map[string]string{"app": "app"}},
			Destination: flow.Endpoint{Namespace: "ns", PodName: "svc-2", Labels: map[string]string{"app": "svc"}},
			Layer4:    flow.Layer4{DestPort: 9999}, // no protocol field set
		},
	}

	got := ComputePatterns(flows, Workloads{})
	assert.Equal(t, 1, len(got))
	assert.Equal(t, "ns/app -> ns/svc:9999/UNKNOWN", got[0].Key)
	assert.Equal(t, "UNKNOWN", got[0].Protocol)
}

func TestComputePatterns_WorkloadResolution(t *testing.T) {
	t.Parallel()
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	flows := []flow.Flow{
		{
			Time:      baseTime,
			Direction: flow.Ingress,
			Source:    flow.Endpoint{Namespace: "default", PodName: "frontend-abcdef12345"},
			Destination: flow.Endpoint{
				Namespace: "production",
				PodName:   "backend-99887766554",
				Labels:    map[string]string{"app": "backend"},
			},
			Layer4: flow.Layer4{DestPort: 443, Protocol: flow.TCP},
		},
	}

	got := ComputePatterns(flows, Workloads{})
	assert.Equal(t, 1, len(got))
	assert.Equal(t, "default/frontend", got[0].SrcWorkloadID)
	assert.Equal(t, "production/backend", got[0].DstWorkloadID)
}

func TestComputePatterns_DifferentFlowsSameKey(t *testing.T) {
	t.Parallel()
	// Flows from different pod instances but same workload should group together
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	flows := []flow.Flow{
		{
			Time:      baseTime,
			Direction: flow.Ingress,
			Source:    flow.Endpoint{Namespace: "production", PodName: "frontend-aaa", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "production", PodName: "backend-bbb", Labels: map[string]string{"app": "backend"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
		},
		{
			Time:      baseTime.Add(1 * time.Minute),
			Direction: flow.Ingress,
			Source:    flow.Endpoint{Namespace: "production", PodName: "frontend-ccc", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "production", PodName: "backend-ddd", Labels: map[string]string{"app": "backend"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
		},
	}

	got := ComputePatterns(flows, Workloads{})
	assert.Equal(t, 1, len(got))
	assert.Equal(t, uint64(2), got[0].Count)
	assert.Equal(t, "production/frontend -> production/backend:8080/TCP", got[0].Key)
}

func TestComputePatterns_PortAndProtocolDistinct(t *testing.T) {
	t.Parallel()
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	flows := []flow.Flow{
		{
			Time:      baseTime,
			Direction: flow.Egress,
			Source:    flow.Endpoint{Namespace: "default", PodName: "app-1", Labels: map[string]string{"app": "myapp"}},
			Destination: flow.Endpoint{Namespace: "default", PodName: "svc-1", Labels: map[string]string{"app": "myservice"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
		},
		{
			Time:      baseTime.Add(1 * time.Minute),
			Direction: flow.Egress,
			Source:    flow.Endpoint{Namespace: "default", PodName: "app-1", Labels: map[string]string{"app": "myapp"}},
			Destination: flow.Endpoint{Namespace: "default", PodName: "svc-1", Labels: map[string]string{"app": "myservice"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.UDP},
		},
		{
			Time:      baseTime.Add(2 * time.Minute),
			Direction: flow.Egress,
			Source:    flow.Endpoint{Namespace: "default", PodName: "app-1", Labels: map[string]string{"app": "myapp"}},
			Destination: flow.Endpoint{Namespace: "default", PodName: "svc-1", Labels: map[string]string{"app": "myservice"}},
			Layer4:    flow.Layer4{DestPort: 9090, Protocol: flow.TCP},
		},
	}

	got := ComputePatterns(flows, Workloads{})
	// TCP:8080, UDP:8080, TCP:9090 should be 3 distinct patterns
	assert.Equal(t, 3, len(got))

	// Verify keys are in sorted order
	for i := 1; i < len(got); i++ {
		assert.Less(t, got[i-1].Key, got[i].Key)
	}

	// TCP:9090 should have count 1
	for _, p := range got {
		if p.Port == 9090 && p.Protocol == "TCP" {
			assert.Equal(t, uint64(1), p.Count)
		}
	}
}

func TestSortByCount(t *testing.T) {
	t.Parallel()
	patterns := []Pattern{
		{Key: "a", Count: 3},
		{Key: "b", Count: 7},
		{Key: "c", Count: 1},
		{Key: "d", Count: 7},
		{Key: "e", Count: 3},
		{Key: "f", Count: 5},
	}

	got := SortByCount(patterns)

	assert.Equal(t, uint64(7), got[0].Count)
	assert.Equal(t, uint64(7), got[1].Count)
	// Tiebreaker on count 7: "b" < "d"
	assert.Equal(t, "b", got[0].Key)
	assert.Equal(t, "d", got[1].Key)

	assert.Equal(t, uint64(5), got[2].Count)
	assert.Equal(t, uint64(3), got[3].Count)
	assert.Equal(t, uint64(3), got[4].Count)
	// Tiebreaker on count 3: "a" < "e"
	assert.Equal(t, "a", got[3].Key)
	assert.Equal(t, "e", got[4].Key)

	assert.Equal(t, uint64(1), got[5].Count)
}

func TestSortByCount_Empty(t *testing.T) {
	t.Parallel()
	got := SortByCount([]Pattern{})
	assert.NotNil(t, got)
	assert.Empty(t, got)
}

func TestSortByCount_Single(t *testing.T) {
	t.Parallel()
	patterns := []Pattern{{Key: "only", Count: 42}}
	got := SortByCount(patterns)
	assert.Equal(t, 1, len(got))
	assert.Equal(t, "only", got[0].Key)
}

func TestFilterDirection(t *testing.T) {
	t.Parallel()
	patterns := []Pattern{
		{Key: "a", Direction: flow.Ingress, Count: 1},
		{Key: "b", Direction: flow.Egress, Count: 2},
		{Key: "c", Direction: flow.Ingress, Count: 3},
		{Key: "d", Direction: flow.Internal, Count: 4},
		{Key: "e", Direction: flow.Egress, Count: 5},
	}

	ingress := FilterDirection(patterns, flow.Ingress)
	assert.Equal(t, 2, len(ingress))
	assert.Equal(t, "a", ingress[0].Key)
	assert.Equal(t, "c", ingress[1].Key)

	egress := FilterDirection(patterns, flow.Egress)
	assert.Equal(t, 2, len(egress))
	assert.Equal(t, "b", egress[0].Key)
	assert.Equal(t, "e", egress[1].Key)

	// Filter with no matches
	internalOnly := FilterDirection(patterns, "BOGUS")
	assert.Empty(t, internalOnly)
	assert.NotNil(t, internalOnly)
}

func TestFilterDirection_Empty(t *testing.T) {
	t.Parallel()
	got := FilterDirection([]Pattern{}, flow.Ingress)
	assert.Empty(t, got)
	assert.NotNil(t, got)
}

func TestFilterDirection_NoCutThrough(t *testing.T) {
	t.Parallel()
	// FilterDirection should never return more elements than input
	patterns := []Pattern{
		{Direction: flow.Ingress},
		{Direction: flow.Ingress},
		{Direction: flow.Egress},
	}
	result := FilterDirection(patterns, "EGRESS")
	assert.LessOrEqual(t, len(result), len(patterns))
}

func TestComputePatterns_ByteAggregation(t *testing.T) {
	t.Parallel()
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	flows := []flow.Flow{
		{
			Time:      baseTime,
			Direction: flow.Ingress,
			Source:    flow.Endpoint{Namespace: "default", PodName: "app-1", Labels: map[string]string{"app": "app"}},
			Destination: flow.Endpoint{Namespace: "default", PodName: "svc-1", Labels: map[string]string{"app": "svc"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Bytes:     100,
		},
		{
			Time:      baseTime.Add(1 * time.Minute),
			Direction: flow.Ingress,
			Source:    flow.Endpoint{Namespace: "default", PodName: "app-1", Labels: map[string]string{"app": "app"}},
			Destination: flow.Endpoint{Namespace: "default", PodName: "svc-1", Labels: map[string]string{"app": "svc"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Bytes:     200,
		},
		{
			Time:      baseTime.Add(2 * time.Minute),
			Direction: flow.Ingress,
			Source:    flow.Endpoint{Namespace: "default", PodName: "app-1", Labels: map[string]string{"app": "app"}},
			Destination: flow.Endpoint{Namespace: "default", PodName: "svc-1", Labels: map[string]string{"app": "svc"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Bytes:     300,
		},
	}

	got := ComputePatterns(flows, Workloads{})
	assert.Equal(t, 1, len(got))
	assert.Equal(t, uint64(3), got[0].Count)
	assert.Equal(t, uint64(600), got[0].Bytes)
}

func TestComputePatterns_NilWorkloads(t *testing.T) {
	t.Parallel()
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	flows := []flow.Flow{
		{
			Time:      baseTime,
			Direction: flow.Ingress,
			Source:    flow.Endpoint{Namespace: "default", PodName: "app-1", Labels: map[string]string{"app": "app"}},
			Destination: flow.Endpoint{Namespace: "default", PodName: "svc-1", Labels: map[string]string{"app": "svc"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
		},
	}

	// Should not panic with nil Workloads
	got := ComputePatterns(flows, nil)
	assert.Equal(t, 1, len(got))
}

func TestComputePatterns_WorkloadsPassedButUnused(t *testing.T) {
	t.Parallel()
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	flows := []flow.Flow{
		{
			Time:      baseTime,
			Direction: flow.Ingress,
			Source:    flow.Endpoint{Namespace: "default", PodName: "app-1", Labels: map[string]string{"app": "app"}},
			Destination: flow.Endpoint{Namespace: "default", PodName: "svc-1", Labels: map[string]string{"app": "svc"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
		},
	}

	workloads := Workloads{
		"default/app": {Name: "app", Namespace: "default", Labels: map[string]string{"app": "app"}},
		"default/svc": {Name: "svc", Namespace: "default", Labels: map[string]string{"app": "svc"}},
	}

	got := ComputePatterns(flows, workloads)
	assert.Equal(t, 1, len(got))
}

func TestComputePatterns_TimeInversion(t *testing.T) {
	t.Parallel()

	// Flows arrive out of order — FirstSeen/LastSeen must still be correct.
	baseTime := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	laterTime := baseTime.Add(2 * time.Hour)
	earliest := baseTime.Add(-1 * time.Hour)
	latest := baseTime.Add(4 * time.Hour)

	flows := []flow.Flow{
		{Time: laterTime, Direction: flow.Egress, Source: flow.Endpoint{Namespace: "n", PodName: "a-1", Labels: map[string]string{"app": "a"}}, Destination: flow.Endpoint{Namespace: "n", PodName: "b-1", Labels: map[string]string{"app": "b"}}, Layer4: flow.Layer4{DestPort: 80, Protocol: flow.TCP}},
		{Time: earliest, Direction: flow.Egress, Source: flow.Endpoint{Namespace: "n", PodName: "a-1", Labels: map[string]string{"app": "a"}}, Destination: flow.Endpoint{Namespace: "n", PodName: "b-1", Labels: map[string]string{"app": "b"}}, Layer4: flow.Layer4{DestPort: 80, Protocol: flow.TCP}},
		{Time: latest, Direction: flow.Egress, Source: flow.Endpoint{Namespace: "n", PodName: "a-1", Labels: map[string]string{"app": "a"}}, Destination: flow.Endpoint{Namespace: "n", PodName: "b-1", Labels: map[string]string{"app": "b"}}, Layer4: flow.Layer4{DestPort: 80, Protocol: flow.TCP}},
	}

	got := ComputePatterns(flows, Workloads{})
	assert.Equal(t, 1, len(got))
	assert.Equal(t, earliest, got[0].FirstSeen)
	assert.Equal(t, latest, got[0].LastSeen)
}

func TestComputePatterns_MultipleProtocols(t *testing.T) {
	t.Parallel()
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name  string
		proto flow.Protocol
	}{
		{"TCP", flow.TCP},
		{"UDP", flow.UDP},
		{"ICMP", flow.ICMP},
		{"SCTP", flow.SCTP},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			flows := []flow.Flow{
				{
					Time:      baseTime,
					Direction: flow.Ingress,
					Source:    flow.Endpoint{Namespace: "a", PodName: "x-1", Labels: map[string]string{"app": "x"}},
					Destination: flow.Endpoint{Namespace: "a", PodName: "y-1", Labels: map[string]string{"app": "y"}},
					Layer4:    flow.Layer4{DestPort: 80, Protocol: tt.proto},
				},
			}
			got := ComputePatterns(flows, Workloads{})
			assert.Equal(t, 1, len(got))
			assert.Equal(t, string(tt.proto), got[0].Protocol)
		})
	}
}

func TestComputePatterns_LargeCount(t *testing.T) {
	t.Parallel()
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	flows := make([]flow.Flow, 1000)
	for i := range flows {
		flows[i] = flow.Flow{
			Time:      baseTime.Add(time.Duration(i) * time.Second),
			Direction: flow.Ingress,
			Source:    flow.Endpoint{Namespace: "default", PodName: "frontend-1", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "default", PodName: "backend-1", Labels: map[string]string{"app": "backend"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Bytes:     4096,
		}
	}

	got := ComputePatterns(flows, Workloads{})
	assert.Equal(t, 1, len(got))
	assert.Equal(t, uint64(1000), got[0].Count)
	assert.Equal(t, uint64(4096000), got[0].Bytes)
}

// Test that SortByCount doesn't panic on nil.
func TestSortByCount_Nil(t *testing.T) {
	t.Parallel()
	got := SortByCount(nil)
	assert.NotNil(t, got)
}

// Test that FilterDirection doesn't panic on nil.
func TestFilterDirection_Nil(t *testing.T) {
	got := FilterDirection(nil, flow.Ingress)
	assert.Empty(t, got)
	assert.NotNil(t, got)
}

// TestComputePatterns_DeterministicOutput runs the same test twice to verify
// that output is byte-identical across calls. This is the determinism guard.
func TestComputePatterns_DeterministicOutput(t *testing.T) {
	t.Parallel()
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	flows := []flow.Flow{
		{
			Time:      baseTime.Add(5 * time.Minute),
			Direction: flow.Ingress,
			Source:    flow.Endpoint{Namespace: "production", PodName: "frontend-aaa", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "production", PodName: "backend-bbb", Labels: map[string]string{"app": "backend"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Bytes:     1000,
		},
		{
			Time:      baseTime,
			Direction: flow.Egress,
			Source:    flow.Endpoint{Namespace: "staging", PodName: "test-ccc", Labels: map[string]string{"app": "test"}},
			Destination: flow.Endpoint{Namespace: "production", PodName: "backend-bbb", Labels: map[string]string{"app": "backend"}},
			Layer4:    flow.Layer4{DestPort: 443, Protocol: flow.TCP},
			Bytes:     2000,
		},
		{
			Time:      baseTime.Add(10 * time.Minute),
			Direction: flow.Ingress,
			Source:    flow.Endpoint{Namespace: "production", PodName: "frontend-ddd", Labels: map[string]string{"app": "frontend"}},
			Destination: flow.Endpoint{Namespace: "production", PodName: "backend-eee", Labels: map[string]string{"app": "backend"}},
			Layer4:    flow.Layer4{DestPort: 8080, Protocol: flow.TCP},
			Bytes:     3000,
		},
	}

	got1 := ComputePatterns(flows, Workloads{})
	got2 := ComputePatterns(flows, Workloads{})

	assert.Equal(t, got1, got2, "ComputePatterns must produce deterministic output for identical input")
}

// TestSortByCount_Stable verifies sort stability.
func TestSortByCount_Stable(t *testing.T) {
	t.Parallel()
	patterns := []Pattern{
		{Key: "z", Count: 5},
		{Key: "a", Count: 5},
		{Key: "m", Count: 5},
	}

	SortByCount(patterns)

	// With same count, tiebreaker is key ascending
	assert.Equal(t, "a", patterns[0].Key)
	assert.Equal(t, "m", patterns[1].Key)
	assert.Equal(t, "z", patterns[2].Key)
}

func TestPattern_DeterministicKeyOrder(t *testing.T) {
	t.Parallel()
	// Test that the pattern key is deterministic regardless of map iteration order.
	// We do this by running the test multiple times — map iteration is randomized.
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	flows := []flow.Flow{
		{
			Time:      baseTime,
			Direction: flow.Ingress,
			Source:    flow.Endpoint{Namespace: "ns1", PodName: "pod-a-1", Labels: map[string]string{"app": "alpha"}},
			Destination: flow.Endpoint{Namespace: "ns2", PodName: "pod-b-1", Labels: map[string]string{"app": "beta"}},
			Layer4:    flow.Layer4{DestPort: 443, Protocol: flow.TCP},
		},
		{
			Time:      baseTime.Add(1 * time.Second),
			Direction: flow.Egress,
			Source:    flow.Endpoint{Namespace: "ns2", PodName: "pod-c-1", Labels: map[string]string{"app": "charlie"}},
			Destination: flow.Endpoint{Namespace: "ns1", PodName: "pod-d-1", Labels: map[string]string{"app": "delta"}},
			Layer4:    flow.Layer4{DestPort: 80, Protocol: flow.UDP},
		},
	}

	keys1 := ComputePatterns(flows, Workloads{})
	keys2 := ComputePatterns(flows, Workloads{})
	keys3 := ComputePatterns(flows, Workloads{})
	keys4 := ComputePatterns(flows, Workloads{})
	keys5 := ComputePatterns(flows, Workloads{})

	// All 5 runs must produce identical results (deterministic despite map internals)
	assert.Equal(t, keys1, keys2, "determinism run 1 vs 2")
	assert.Equal(t, keys1, keys3, "determinism run 1 vs 3")
	assert.Equal(t, keys1, keys4, "determinism run 1 vs 4")
	assert.Equal(t, keys1, keys5, "determinism run 1 vs 5")

	var total uint64
	for _, k := range keys1 {
		total += k.Count
	}
	assert.Equal(t, uint64(2), total, "total count should be 2")
}

package analyze

import (
	"testing"

	"github.com/flowguarder/flowguarder/pkg/flow"
	"github.com/stretchr/testify/assert"
)

func TestResolveWorkload(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		endpoint flow.Endpoint
		wantName string
		wantKind WorkloadKind
		wantNS   string
	}{
		{
			name: "app label resolves name",
			endpoint: flow.Endpoint{
				Namespace: "production",
				PodName:   "frontend-7d3f9abc",
				Labels:    map[string]string{"app": "frontend"},
			},
			wantName: "frontend",
			wantKind: Deployment,
			wantNS:   "production",
		},
		{
			name: "app.kubernetes.io/name label resolves name",
			endpoint: flow.Endpoint{
				Namespace: "staging",
				PodName:   "api-6b8c7d9e0f-xyz99",
				Labels:    map[string]string{"app.kubernetes.io/name": "api"},
			},
			wantName: "api",
			wantKind: Deployment,
			wantNS:   "staging",
		},
		{
			name: "app.kubernetes.io/component resolves name",
			endpoint: flow.Endpoint{
				Namespace: "default",
				PodName:   "web-server-abc123",
				Labels:    map[string]string{"app": "web", "app.kubernetes.io/component": "server"},
			},
			wantName: "web",
			wantKind: Deployment,
			wantNS:   "default",
		},
		{
			name: "controller-uid resolves name and sets CronJob kind",
			endpoint: flow.Endpoint{
				Namespace: "default",
				PodName:   "cronjob-abc123",
				Labels: map[string]string{
					"app":            "cronjob",
					"controller-uid": "abc12345-def6-7890-ghij-klmnopqrstuv",
				},
			},
			wantName: "cronjob",
			wantKind: CronJob,
			wantNS:   "default",
		},
		{
			name: "job-name label resolves name and sets CronJob kind",
			endpoint: flow.Endpoint{
				Namespace: "prod",
				PodName:   "cleanup-cron-1720000000-abcde",
				Labels:    map[string]string{"job-name": "cleanup-cron-1720000000"},
			},
			wantName: "cleanup-cron",
			wantKind: CronJob,
			wantNS:   "prod",
		},
		{
			name: "k8s-app label sets DaemonSet kind",
			endpoint: flow.Endpoint{
				Namespace: "kube-system",
				PodName:   "node-agent-x9y8z",
				Labels:    map[string]string{"k8s-app": "node-agent"},
			},
			wantName: "node-agent",
			wantKind: DaemonSet,
			wantNS:   "kube-system",
		},
		{
			name: "no labels falls back to pod-name prefix",
			endpoint: flow.Endpoint{
				Namespace: "default",
				PodName:   "frontend-7d3f9abc",
				Labels:    nil,
			},
			wantName: "frontend",
			wantKind: Unknown,
			wantNS:   "default",
		},
		{
			name: "no labels single word pod falls back to full name",
			endpoint: flow.Endpoint{
				Namespace: "default",
				PodName:   "single",
				Labels:    nil,
			},
			wantName: "single",
			wantKind: Unknown,
			wantNS:   "default",
		},
		{
			name: "name label resolves name",
			endpoint: flow.Endpoint{
				Namespace: "monitoring",
				PodName:   "prometheus-server-abc",
				Labels:    map[string]string{"name": "prometheus-server"},
			},
			wantName: "prometheus-server",
			wantKind: Unknown,
			wantNS:   "monitoring",
		},
		{
			name: "StripPodTemplateHash from label value",
			endpoint: flow.Endpoint{
				Namespace: "default",
				PodName:   "cache-5d4f9b8c7-xyz12",
				Labels:    map[string]string{"app": "cache-5d4f9b8c7"},
			},
			wantName: "cache",
			wantKind: Deployment,
			wantNS:   "default",
		},
		{
			name: "Empty labels map instead of nil",
			endpoint: flow.Endpoint{
				Namespace: "default",
				PodName:   "redis-cache-7f8a9b0c1",
				Labels:    map[string]string{},
			},
			wantName: "redis-cache",
			wantKind: Unknown,
			wantNS:   "default",
		},
		{
			name: "k8s:app fallback resolves name when plain app absent",
			endpoint: flow.Endpoint{
				Namespace: "default",
				PodName:   "",
				Labels:    map[string]string{"k8s:app": "demo-client"},
			},
			wantName: "demo-client",
			wantKind: Unknown,
			wantNS:   "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ResolveWorkload(tt.endpoint)
			assert.Equal(t, tt.wantName, got.Name, "Workload name mismatch")
			assert.Equal(t, tt.wantKind, got.Kind, "Workload kind mismatch")
			assert.Equal(t, tt.wantNS, got.Namespace, "Workload namespace mismatch")
		})
	}
}

func TestWorkloadIDConversion(t *testing.T) {
	t.Parallel()
	w := Workload{
		Name:      "frontend",
		Namespace: "production",
		Labels:    map[string]string{"app": "frontend"},
		Kind:      Deployment,
	}
	assert.Equal(t, "production/frontend", StringWorkloadID(w))
}

// StringWorkloadID returns the namespace/name string for a workload.
func StringWorkloadID(w Workload) string {
	return string(WorkloadID(w.Namespace + "/" + w.Name))
}

func TestStripPodTemplateHash(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"standard hash 10 hex chars", "deployment-5d4f9b8c7d", "deployment"},
		{"shorter hash 8 hex chars", "api-7d3f9abc", "api"},
		{"legacy alphanumeric", "worker-abc1234567", "worker"},
		{"no hash - just name", "frontend", "frontend"},
		{"dash but not a hash", "my-app", "my-app"},
		{"two hashes - only trailing", "backend-abc12345-67890123", "backend-abc12345"},
		{"empty string", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := StripPodTemplateHash(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestWorkloadNameFromPodName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// --- Acceptance cases from plan ---
		{"multi-segment + hash + pod", "local-path-provisioner-7dc846544d-cn4kb", "local-path-provisioner"},
		{"single-segment + template-hash + pod", "coredns-668d6bf9bc-abcde", "coredns-668d6bf9bc"},
		{"multi-segment + template-hash + pod", "demo-client-6d5fd48c7d-tnjbp", "demo-client"},
		{"single-segment only", "single", "single"},
		{"multi-segment with pod-hash only", "api-gw-pqr55", "api-gw"},
		// --- Existing: must keep passing ---
		{"frontend-7d3f9abc", "frontend-7d3f9abc", "frontend"},
		{"empty", "", ""},
		// --- Updated expectations (new semantics) ---
		{"a-b-c-d: no hash suffix, multi-segment preserved", "a-b-c-d", "a-b-c-d"},
		{"cache-1: plain ordinal is not a template hash", "cache-1", "cache-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := WorkloadNameFromPodName(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestAggregate(t *testing.T) {
	t.Parallel()
	flows := []flow.Flow{
		{
			Source: flow.Endpoint{
				Namespace: "production",
				PodName:   "frontend-7d3f9abc",
				Labels:    map[string]string{"app": "frontend"},
			},
			Destination: flow.Endpoint{
				Namespace: "production",
				PodName:   "backend-5d4f9b8c7d",
				Labels:    map[string]string{"app": "backend"},
			},
		},
		{
			Source: flow.Endpoint{
				Namespace: "production",
				PodName:   "frontend-8e4a0bcd",
				Labels:    map[string]string{"app": "frontend"},
			},
			Destination: flow.Endpoint{
				Namespace: "production",
				PodName:   "backend-6e5a9c8d7e",
				Labels:    map[string]string{"app": "backend"},
			},
		},
		{
			Source: flow.Endpoint{
				Namespace: "staging",
				PodName:   "test-runner-abc",
				Labels:    map[string]string{"app": "test-runner"},
			},
			Destination: flow.Endpoint{
				Namespace: "production",
				PodName:   "backend-5d4f9b8c7d",
				Labels:    map[string]string{"app": "backend"},
			},
		},
	}

	result := Aggregate(flows)

	// Should have exactly 2 unique workloads: frontend and backend
	// test-runner is in staging, so it's a separate workload
	assert.Equal(t, 3, len(result), "Expected 3 unique workloads")

	// Verify frontend exists
	frontendID := WorkloadID("production/frontend")
	assert.Contains(t, result, frontendID)
	assert.Equal(t, Deployment, result[frontendID].Kind)

	// Verify backend exists
	backendID := WorkloadID("production/backend")
	assert.Contains(t, result, backendID)
	assert.Equal(t, Deployment, result[backendID].Kind)

	// Verify test-runner exists
	testRunnerID := WorkloadID("staging/test-runner")
	assert.Contains(t, result, testRunnerID)
	assert.Equal(t, Deployment, result[testRunnerID].Kind)
}

func TestAggregateEmpty(t *testing.T) {
	t.Parallel()
	result := Aggregate(nil)
	assert.Empty(t, result, "Empty flows should produce empty workloads")

	result2 := Aggregate([]flow.Flow{})
	assert.Empty(t, result2, "Nil slice flows should produce empty workloads")
}

func TestDetectKind(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		labels   map[string]string
		expected WorkloadKind
	}{
		{"job-name → CronJob", map[string]string{"job-name": "backup"}, CronJob},
		{"controller-uid → CronJob", map[string]string{"controller-uid": "abc123"}, CronJob},
		{"k8s-app → DaemonSet", map[string]string{"k8s-app": "node-exporter"}, DaemonSet},
		{"app → Deployment", map[string]string{"app": "web"}, Deployment},
		{"app.kubernetes.io/name → Deployment", map[string]string{"app.kubernetes.io/name": "api"}, Deployment},
		{"no kind labels → Unknown", map[string]string{"version": "v1"}, Unknown},
		{"empty labels → Unknown", map[string]string{}, Unknown},
		{"nil labels → Unknown", nil, Unknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := detectKind(tt.labels)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestSortedWorkloadIDs(t *testing.T) {
	t.Parallel()
	w := Workloads{
		"production/zoo": {Name: "zoo", Namespace: "production"},
		"default/alpha":  {Name: "alpha", Namespace: "default"},
		"staging/bravo":  {Name: "bravo", Namespace: "staging"},
		"default/abc":    {Name: "abc", Namespace: "default"},
	}

	ids := w.SortedIDs()
	expected := []string{
		"default/abc",
		"default/alpha",
		"production/zoo",
		"staging/bravo",
	}
	assert.Equal(t, expected, ids, "Workload IDs should be sorted deterministically")
}

func TestParseServiceHint(t *testing.T) {
	t.Parallel()
	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		ns, name, ok := ParseServiceHint("default/kubernetes")
		assert.True(t, ok)
		assert.Equal(t, "default", ns)
		assert.Equal(t, "kubernetes", name)
	})
	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		_, _, ok := ParseServiceHint("")
		assert.False(t, ok)
	})
	t.Run("no slash", func(t *testing.T) {
		t.Parallel()
		_, _, ok := ParseServiceHint("onlyname")
		assert.False(t, ok)
	})
	t.Run("trailing slash", func(t *testing.T) {
		t.Parallel()
		_, _, ok := ParseServiceHint("default/")
		assert.False(t, ok)
	})
	t.Run("whitespace trimmed", func(t *testing.T) {
		t.Parallel()
		ns, name, ok := ParseServiceHint("  default/svc  ")
		assert.True(t, ok)
		assert.Equal(t, "default", ns)
		assert.Equal(t, "svc", name)
	})
}

func TestResolveFromLabel(t *testing.T) {
	t.Parallel()
	e := flow.Endpoint{Labels: map[string]string{"app.kubernetes.io/service-name": "my-svc"}}
	assert.Equal(t, "my-svc", ResolveFromLabel(e))
	assert.Equal(t, "", ResolveFromLabel(flow.Endpoint{Labels: nil}))
	assert.Equal(t, "", ResolveFromLabel(flow.Endpoint{}))
}

func TestHintResolver(t *testing.T) {
	t.Parallel()
	r := NewHintResolver()
	src, dst := r.Resolve(flow.Flow{
		Source:      flow.Endpoint{Service: "default/svc-src"},
		Destination: flow.Endpoint{Service: "kube-system/coredns"},
	})
	assert.Equal(t, "default/svc-src", src)
	assert.Equal(t, "kube-system/coredns", dst)
}

func TestAggregateDeterministic(t *testing.T) {
	t.Parallel()
	// Same flows in different order should produce the same workload set
	flows1 := []flow.Flow{
		{
			Source:      flow.Endpoint{Namespace: "default", PodName: "a-123", Labels: map[string]string{"app": "alpha"}},
			Destination: flow.Endpoint{Namespace: "default", PodName: "b-456", Labels: map[string]string{"app": "beta"}},
		},
		{
			Source:      flow.Endpoint{Namespace: "default", PodName: "b-789", Labels: map[string]string{"app": "beta"}},
			Destination: flow.Endpoint{Namespace: "default", PodName: "c-012", Labels: map[string]string{"app": "gamma"}},
		},
		{
			Source:      flow.Endpoint{Namespace: "default", PodName: "c-345", Labels: map[string]string{"app": "gamma"}},
			Destination: flow.Endpoint{Namespace: "default", PodName: "a-678", Labels: map[string]string{"app": "alpha"}},
		},
	}

	flows2 := []flow.Flow{
		{
			Source:      flow.Endpoint{Namespace: "default", PodName: "c-345", Labels: map[string]string{"app": "gamma"}},
			Destination: flow.Endpoint{Namespace: "default", PodName: "a-678", Labels: map[string]string{"app": "alpha"}},
		},
		{
			Source:      flow.Endpoint{Namespace: "default", PodName: "b-789", Labels: map[string]string{"app": "beta"}},
			Destination: flow.Endpoint{Namespace: "default", PodName: "c-012", Labels: map[string]string{"app": "gamma"}},
		},
		{
			Source:      flow.Endpoint{Namespace: "default", PodName: "a-123", Labels: map[string]string{"app": "alpha"}},
			Destination: flow.Endpoint{Namespace: "default", PodName: "b-456", Labels: map[string]string{"app": "beta"}},
		},
	}

	r1 := Aggregate(flows1)
	r2 := Aggregate(flows2)

	assert.Equal(t, len(r1), len(r2), "Different input orders should produce same count")
	for id := range r1 {
		assert.Equal(t, r1[id].Name, r2[id].Name, "Same workload ID should have same name")
		assert.Equal(t, r1[id].Kind, r2[id].Kind, "Same workload ID should have same kind")
	}
}

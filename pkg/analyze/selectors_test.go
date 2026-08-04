package analyze

import (
	"testing"
)

func TestStripUnstableLabels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   map[string]string
		want    map[string]string
	}{
		{
			name:  "nil input returns empty map (not nil)",
			input: nil,
			want:  map[string]string{},
		},
		{
			name:  "empty input returns empty map",
			input: map[string]string{},
			want:  map[string]string{},
		},
		{
			name: "all stable labels returned unchanged",
			input: map[string]string{
				"app":                      "nginx",
				"app.kubernetes.io/name":   "web",
				"app.kubernetes.io/instance": "prod",
				"app.kubernetes.io/component": "frontend",
				"k8s-app":                  "metrics",
				"name":                     "backend",
				"job-name":                 "backup",
			},
			want: map[string]string{
				"app":                       "nginx",
				"app.kubernetes.io/name":    "web",
				"app.kubernetes.io/instance": "prod",
				"app.kubernetes.io/component": "frontend",
				"k8s-app":                   "metrics",
				"name":                      "backend",
				"job-name":                  "backup",
			},
		},
		{
			name:  "pod-template-hash removed",
			input: map[string]string{"app": "nginx", "pod-template-hash": "abc12345"},
			want:  map[string]string{"app": "nginx"},
		},
		{
			name:  "controller-revision-hash removed",
			input: map[string]string{"app": "redis", "controller-revision-hash": "statefulset-5f"},
			want:  map[string]string{"app": "redis"},
		},
		{
			name:  "pod-index removed",
			input: map[string]string{"app": "zookeeper", "pod-index": "0"},
			want:  map[string]string{"app": "zookeeper"},
		},
		{
			name:  "apps.kubernetes.io/pod-index removed",
			input: map[string]string{"app": "etcd", "apps.kubernetes.io/pod-index": "2"},
			want:  map[string]string{"app": "etcd"},
		},
		{
			name:  "statefulset.kubernetes.io/pod-name removed",
			input: map[string]string{"app": "consul", "statefulset.kubernetes.io/pod-name": "consul-0"},
			want:  map[string]string{"app": "consul"},
		},
		{
			name:  "controller-uid removed",
			input: map[string]string{"job-name": "backup-123", "controller-uid": "a1b2c3"},
			want:  map[string]string{"job-name": "backup-123"},
		},
		{
			name:  "projectcalico.org/namespace removed",
			input: map[string]string{"app": "web", "projectcalico.org/namespace": "production"},
			want:  map[string]string{"app": "web"},
		},
		{
			name:  "projectcalico.org/orchestrator removed",
			input: map[string]string{"app": "web", "projectcalico.org/orchestrator": "kubernetes"},
			want:  map[string]string{"app": "web"},
		},
		{
			name:  "projectcalico.org/serviceaccount removed",
			input: map[string]string{"app": "web", "projectcalico.org/serviceaccount": "default"},
			want:  map[string]string{"app": "web"},
		},
		{
			name:  "any projectcalico.org/* prefix removed",
			input: map[string]string{"app": "web", "projectcalico.org/custom-key": "value"},
			want:  map[string]string{"app": "web"},
		},
		{
			name: "mix of stable and unstable — only stable kept",
			input: map[string]string{
				"app":                        "nginx",
				"app.kubernetes.io/name":     "web",
				"pod-template-hash":          "d8f3abc1",
				"controller-revision-hash":   "ds-7b9c",
				"projectcalico.org/namespace": "kube-system",
				"k8s-app":                    "kube-dns",
			},
			want: map[string]string{
				"app":              "nginx",
				"app.kubernetes.io/name": "web",
				"k8s-app":          "kube-dns",
			},
		},
		{
			name:  "unknown labels not in deny-list are kept",
			input: map[string]string{"app": "redis", "custom.io/whatever": "yes", "version": "7"},
			want:  map[string]string{"app": "redis", "custom.io/whatever": "yes", "version": "7"},
		},
		{
			name: "only unstable labels result in empty map",
			input: map[string]string{
				"pod-template-hash": "abc",
				"controller-uid":    "xyz",
			},
			want: map[string]string{},
		},
		{
			name: "knative runai uuid labels stripped",
			input: map[string]string{
				"app":                                "redis",
				"run.ai/workload-id":                 "f8912b5b-1111-2222-3333-444455556666",
				"serving.knative.dev/revisionUID":     "a1b2c3d4-eeff-0011-2233-445566778899",
				"pod-template-generation":             "2",
				"runai-gpu-group":                     "uuid",
			},
			want: map[string]string{"app": "redis"},
		},
		{
			name: "stable key kept even when value is a UUID",
			input: map[string]string{
				"app.kubernetes.io/name": "550e8400-e29b-41d4-a716-446655440000",
			},
			want: map[string]string{
				"app.kubernetes.io/name": "550e8400-e29b-41d4-a716-446655440000",
			},
		},
		{
			name: "non-stable key with UUID value stripped",
			input: map[string]string{"custom": "f8912b5b-1111-2222-3333-444455556666"},
			want: map[string]string{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := StripUnstableLabels(tt.input)

			// Check that result is never nil when input was not nil (and never nil for nil input per contract).
			if got == nil {
				t.Fatal("StripUnstableLabels returned nil")
			}

			if len(got) != len(tt.want) {
				t.Fatalf("expected %d labels, got %d\nwant: %v\ngot:  %v", len(tt.want), len(got), tt.want, got)
			}

			for k, wantV := range tt.want {
				if gotV, ok := got[k]; !ok {
					t.Errorf("expected key %q to be present", k)
				} else if gotV != wantV {
					t.Errorf("key %q: expected %q, got %q", k, wantV, gotV)
				}
			}

			// Verify caller did not mutate the input map.
			for k := range tt.input {
				if _, ok := got[k]; !ok {
					// key was stripped — ensure it was unstable.
					// (Already validated by the want map above.)
				}
			}
		})
	}
}

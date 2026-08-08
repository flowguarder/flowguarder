package main

import (
	"testing"

	"github.com/flowguarder/flowguarder/pkg/parser"
)

func TestResolvePolicyFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		format   string
		src      parser.Source
		expected string
	}{
		// Auto resolutions (CNI-aware defaults)
		{
			name:     "auto + hubble -> cnp",
			format:   "auto",
			src:      parser.SourceHubble,
			expected: "cnp",
		},
		{
			name:     "auto + calico -> np",
			format:   "auto",
			src:      parser.SourceCalico,
			expected: "np",
		},
		{
			name:     "auto + goldmane -> np",
			format:   "auto",
			src:      parser.SourceGoldmane,
			expected: "np",
		},
		{
			name:     "auto + calico_syslog -> np",
			format:   "auto",
			src:      parser.SourceCalicoSyslog,
			expected: "np",
		},
		{
			name:     "auto + unknown -> np",
			format:   "auto",
			src:      parser.SourceUnknown,
			expected: "np",
		},
		{
			name:     "auto + auto -> np",
			format:   "auto",
			src:      parser.SourceAuto,
			expected: "np",
		},
		// Explicit formats pass through for all sources
		{
			name:     "np + hubble -> np",
			format:   "np",
			src:      parser.SourceHubble,
			expected: "np",
		},
		{
			name:     "cnp + hubble -> cnp",
			format:   "cnp",
			src:      parser.SourceHubble,
			expected: "cnp",
		},
		{
			name:     "np + calico -> np",
			format:   "np",
			src:      parser.SourceCalico,
			expected: "np",
		},
		{
			name:     "cnp + calico -> cnp",
			format:   "cnp",
			src:      parser.SourceCalico,
			expected: "cnp",
		},
		{
			name:     "cnp + goldmane -> cnp",
			format:   "cnp",
			src:      parser.SourceGoldmane,
			expected: "cnp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := resolvePolicyFormat(tt.format, tt.src)
			if got != tt.expected {
				t.Errorf("resolvePolicyFormat(%q, %v) = %q, want %q",
					tt.format, tt.src, got, tt.expected)
			}
		})
	}
}

func TestValidatePolicyFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		format  string
		wantErr bool
	}{
		{
			name:    "auto is valid",
			format:  "auto",
			wantErr: false,
		},
		{
			name:    "np is valid",
			format:  "np",
			wantErr: false,
		},
		{
			name:    "cnp is valid",
			format:  "cnp",
			wantErr: false,
		},
		{
			name:    "yaml is invalid",
			format:  "yaml",
			wantErr: true,
		},
		{
			name:    "empty string is invalid",
			format:  "",
			wantErr: true,
		},
		{
			name:    "cilium is invalid",
			format:  "cilium",
			wantErr: true,
		},
		{
			name:    "cnp-full is invalid",
			format:  "cnp-full",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validatePolicyFormat(tt.format)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePolicyFormat(%q) error = %v, wantErr %v",
					tt.format, err, tt.wantErr)
			}
		})
	}
}

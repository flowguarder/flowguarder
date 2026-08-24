package main

import (
	"bytes"
	"testing"
)

func TestVersionCmd(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		expected string
	}{
		{
			name:     "version command prints only version number",
			expected: "1.4.2\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			buf := new(bytes.Buffer)
			versionCmd.SetOut(buf)

			// Directly invoke Run to avoid cobra parent delegation
			// that triggers help output in test context.
			versionCmd.Run(versionCmd, nil)

			if got := buf.String(); got != tt.expected {
				t.Errorf("output = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestRootHasVersion(t *testing.T) {
	t.Parallel()

	if rootCmd.Version != "1.4.2" {
		t.Errorf("rootCmd.Version = %q, want %q", rootCmd.Version, "1.4.2")
	}
}

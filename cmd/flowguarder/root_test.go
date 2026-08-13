package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRootHelpContainsSkipVisualize(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"--help"})
	rootCmd.Execute()

	help := buf.String()
	if !strings.Contains(help, "--skip-visualize") {
		t.Errorf("root help output does not contain --skip-visualize flag:\n%s", help)
	}

	if !strings.Contains(help, "skip generating flowguarder-visualization.html") {
		t.Errorf("root help output does not contain --skip-visualize description:\n%s", help)
	}
}

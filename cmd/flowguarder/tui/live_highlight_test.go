package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCalicoFilePathTracksHighlight locks the no-Enter contract: the CLI
// preview and runner must use the file currently UNDER THE CURSOR as soon as
// navigation highlights it, without requiring an explicit Enter selection.
//
// Row layout for a non-root cwd: row 0 is the synthetic "..", then entries in
// bubbles order (directories first, then by name). calicoCursorPos indexes
// those rows directly and advances together with the picker's cursor.
func TestCalicoFilePathTracksHighlight(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "flows.jsonl")
	if err := os.WriteFile(file, []byte("{}\n"), 0644); err != nil {
		t.Fatal(err)
	}

	lt := NewLiveTab()
	lt.selector.source = LiveSourceCalico
	lt.calicoFile.CurrentDirectory = dir
	lt.calicoFile.Path = ""

	cases := []struct {
		pos  int
		want string
	}{
		{0, ""},   // ".." (synthetic row)
		{1, ""},   // "sub" directory -> fallback to Enter-selected path
		{2, file}, // "flows.jsonl" highlighted -> used without Enter
	}
	for _, c := range cases {
		lt.calicoCursorPos = c.pos
		if got := lt.CalicoFilePath(); got != c.want {
			t.Errorf("cursor pos %d: CalicoFilePath() = %q, want %q", c.pos, got, c.want)
		}
	}
}

// TestLiveReportsRowMatchesAnalyze pins cross-tab parity on a seeded model
// (same fixture style as the goldens): the Reports block must start on the
// same view row in Analyze and in Live — for both live sources.
func TestLiveReportsRowMatchesAnalyze(t *testing.T) {
	t.Parallel()

	for _, size := range []struct{ w, h int }{
		{120, 40}, {100, 30}, {80, 24}, {140, 50},
	} {
		reportsRow := func(tab Tab, src LiveSource) int {
			m := baseGoldenModel()
			m.width, m.height = size.w, size.h
			if tab == TabLive {
				m.liveTab.selector.source = src
				m.activeArea = AreaLiveInput
			} else {
				m.activeArea = AreaAnalyzePicker
			}
			v := m.View()
			lines := strings.Split(v, "\n")
			for i, l := range lines {
				if strings.Contains(l, "Reports:") {
					return i
				}
			}
			t.Fatalf("Reports: title not found at %dx%d", size.w, size.h)
			return -1
		}

		analyze := reportsRow(TabAnalyze, 0)
		hubble := reportsRow(TabLive, LiveSourceHubble)
		calico := reportsRow(TabLive, LiveSourceCalico)
		if hubble != calico {
			t.Errorf("%dx%d: live sources differ: hubble=%d calico=%d", size.w, size.h, hubble, calico)
		}
		if analyze != hubble {
			t.Errorf("%dx%d: live does not match analyze: analyze=%d live=%d", size.w, size.h, analyze, hubble)
		}
		// Absolute placement: reports start body-row B-R-reportsBottomGap+1,
		// i.e. view index B-R-reportsBottomGap+2 (header+sep above the body).
		bvh := 12
		if avail := size.h - 14; avail < 36 {
			bvh = avail / 3
			if bvh < 3 {
				bvh = 3
			}
		}
		bodyH := size.h - 6 - bvh
		want := bodyH - 7 - reportsBottomGap + 2
		if analyze != want {
			t.Errorf("%dx%d: reports row = %d, want %d (3-line bottom gap)", size.w, size.h, analyze, want)
		}
	}
}

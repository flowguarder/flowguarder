package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/filepicker"
)

// newPopulatedPicker builds a filepicker.Model rooted at a temp directory
// containing a.jsonl and b.jsonl, then drives Init -> cmd() -> Update so the
// internal files snapshot is populated. Using the same model lineage
// guarantees the readDirMsg id matches and Update accepts it.
func newPopulatedPicker(t *testing.T) filepicker.Model {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"a.jsonl", "b.jsonl"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("flow\n"), 0o644); err != nil {
			t.Fatalf("WriteFile(%s): %v", name, err)
		}
	}
	p := filepicker.New()
	p.CurrentDirectory = dir
	p.AutoHeight = false
	p.SetHeight(10)
	cmd := p.Init()
	if cmd == nil {
		t.Fatal("filepicker.Init() returned nil cmd")
	}
	msg := cmd()
	if msg == nil {
		t.Fatal("filepicker Init cmd returned nil msg")
	}
	p2, _ := p.Update(msg)
	return p2
}

// capturePanic runs fn and reports whether it panicked.
func capturePanic(fn func()) (panicked bool) {
	defer func() {
		if recover() != nil {
			panicked = true
		}
	}()
	fn()
	return
}

// TestSafeFilePickerViewRecoversVanishedEntry reproduces the upstream bubbles
// v1.0.0 crash: View() iterates a stale DirEntry snapshot; for an entry that
// vanished after ReadDir, f.Info() returns a nil os.FileInfo interface and
// info.Mode() panics (filepicker.go:385). It then asserts the guard in
// safeFilePickerView turns that crash into a plain-text placeholder.
func TestSafeFilePickerViewRecoversVanishedEntry(t *testing.T) {
	t.Parallel()

	p := newPopulatedPicker(t)
	// Mutate the directory BEHIND the picker's snapshot.
	if err := os.Remove(filepath.Join(p.CurrentDirectory, "a.jsonl")); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	// Old-behavior proof: raw View() still panics on the stale snapshot.
	if !capturePanic(func() { _ = p.View() }) {
		t.Fatal("expected raw filepicker.View() to panic on a vanished entry")
	}

	got := safeFilePickerView(p)
	if !strings.Contains(got, "directory changed") {
		t.Errorf("safeFilePickerView() = %q, want placeholder containing %q", got, "directory changed")
	}
}

// TestSafeFilePickerViewHealthyListingUnchanged asserts the wrapper is
// transparent when no panic occurs: a healthy picker renders its normal
// listing unchanged.
func TestSafeFilePickerViewHealthyListingUnchanged(t *testing.T) {
	t.Parallel()

	p := newPopulatedPicker(t) // both files still on disk

	got := safeFilePickerView(p)
	if !strings.Contains(got, "b.jsonl") {
		t.Errorf("safeFilePickerView() = %q, want normal listing containing %q", got, "b.jsonl")
	}
}

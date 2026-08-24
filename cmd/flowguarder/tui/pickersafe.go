package tui

import (
	"github.com/charmbracelet/bubbles/filepicker"
)

// safeFilePickerView renders p.View() behind a narrow panic guard.
//
// Upstream mechanism: bubbles v1.0.0 filepicker.Model.View iterates the
// os.DirEntry snapshot captured at the last ReadDir (readDirMsg). If an entry
// vanishes from the directory between that snapshot and the next render —
// which happens routinely once our pipelines write policy YAML and the
// visualization HTML into the directory being browsed — f.Info() fails and
// returns a nil os.FileInfo interface value, and View's unconditional
// info.Mode() call panics with a nil pointer dereference
// (filepicker.go:385, bubbles v1.0.0).
//
// The guard lives in our code rather than upstream because v1.0.0 is the
// newest bubbles release (verified via `go list -m -versions`) and exposes no
// Reload/refresh API to re-validate the snapshot before rendering.
//
// On recovery a plain-text placeholder is returned; navigating with
// up/down/enter makes the picker re-ReadDir, rebuilding a consistent
// snapshot. No lipgloss styling is applied so the fallback stays
// deterministic.
func safeFilePickerView(p filepicker.Model) (view string) {
	defer func() {
		if r := recover(); r != nil {
			view = "\n(directory changed — press up/down/enter to refresh)\n"
		}
	}()
	return p.View()
}

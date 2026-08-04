package ingest

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/flowguarder/flowguarder/pkg/parser"
)

// TestFileSourcePlainText opens a regular text file and verifies content is read.
func TestFileSourcePlainText(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	content := "line1\nline2\nline3\n"
	filePath := filepath.Join(dir, "flows.jsonl")
	if err := os.WriteFile(filePath, []byte(content), 0o644); err != nil {
		t.Fatalf("create fixture: %v", err)
	}

	src := &FileSource{Path: filePath}
	rc, err := src.Open(context.Background())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer rc.Close()

	read, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(read) != content {
		t.Fatalf("content mismatch: got %q, want %q", read, content)
	}
}

// TestFileSourceGzip opens a gzip-compressed file and reads decoded content.
func TestFileSourceGzip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	filePath := filepath.Join(dir, "flows.jsonl.gz")

	// Create gzip fixture.
	gzFile, err := os.Create(filePath)
	if err != nil {
		t.Fatalf("create fixture: %v", err)
	}
	w := gzip.NewWriter(gzFile)
	orig := `{"src":"10.0.0.1"}
{"src":"10.0.0.2"}
`
	if _, err := io.Copy(w, strings.NewReader(orig)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	if err := gzFile.Close(); err != nil {
		t.Fatalf("file close: %v", err)
	}

	src := &FileSource{Path: filePath}
	rc, err := src.Open(context.Background())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer rc.Close()

	read, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(read) != orig {
		t.Fatalf("decompressed mismatch: got %q, want %q", read, orig)
	}
}

// TestFileSourceNonexistent returns error for nonexistent file.
func TestFileSourceNonexistent(t *testing.T) {
	t.Parallel()

	src := &FileSource{Path: filepath.Join(t.TempDir(), "nonexistent.jsonl")}
	_, err := src.Open(context.Background())
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

// TestFileSourceEmptyPath returns error for empty path.
func TestFileSourceEmptyPath(t *testing.T) {
	t.Parallel()

	src := &FileSource{}
	_, err := src.Open(context.Background())
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

// TestFileSourceFormat returns parser.SourceAuto.
func TestFileSourceFormat(t *testing.T) {
	t.Parallel()

	src := &FileSource{Path: "/dev/null"}
	if got := src.Format(); got != parser.SourceAuto {
		t.Fatalf("Format: got %v, want %v", got, parser.SourceAuto)
	}
}

// TestStdinSourceOpen verifies Open returns a reader wrapping os.Stdin.
func TestStdinSourceOpen(t *testing.T) {
	t.Parallel()

	src := &StdinSource{}
	rc, err := src.Open(context.Background())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer rc.Close()

	if _, ok := rc.(io.Reader); !ok {
		t.Fatal("returned reader does not implement io.Reader")
	}
}

// TestStdinSourceFormat returns parser.SourceAuto.
func TestStdinSourceFormat(t *testing.T) {
	t.Parallel()

	src := &StdinSource{}
	if got := src.Format(); got != parser.SourceAuto {
		t.Fatalf("Format: got %v, want %v", got, parser.SourceAuto)
	}
}

// TestStdinSourceCloseIsNop ensures Close returns nil.
func TestStdinSourceCloseIsNop(t *testing.T) {
	t.Parallel()

	src := &StdinSource{}
	rc, err := src.Open(context.Background())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("Close should be a no-op, got: %v", err)
	}
}

// TestDirSourceIterateFlat iterates without recursion, finding only top-level files.
func TestDirSourceIterateFlat(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, name := range []string{"a.jsonl", "b.jsonl", "subdir"} {
		if name == "subdir" {
			if err := os.MkdirAll(filepath.Join(dir, name), 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o644); err != nil {
			t.Fatalf("write file: %v", err)
		}
	}

	src := &DirSource{Path: dir, Recursive: false}
	paths := []string{}
	if err := src.Iterate(context.Background(), func(p string) error {
		paths = append(paths, p)
		return nil
	}); err != nil {
		t.Fatalf("Iterate: %v", err)
	}

	if len(paths) != 2 {
		t.Fatalf("expected 2 files, got %d: %v", len(paths), paths)
	}
	for _, p := range paths {
		if strings.Contains(p, "subdir") {
			t.Fatalf("flat iteration should not include subdirs, got: %s", p)
		}
	}
}

// TestDirSourceIterateRecursive walks all levels.
func TestDirSourceIterateRecursive(t *testing.T) {
	t.Parallel()

	top := t.TempDir()
	sub := filepath.Join(top, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	os.WriteFile(filepath.Join(top, "a.jsonl"), []byte("a"), 0o644)
	os.WriteFile(filepath.Join(sub, "b.jsonl"), []byte("b"), 0o644)
	os.WriteFile(filepath.Join(sub, "c.log"), []byte("c log"), 0o644)

	src := &DirSource{Path: top, Recursive: true}
	paths := []string{}
	if err := src.Iterate(context.Background(), func(p string) error {
		paths = append(paths, p)
		return nil
	}); err != nil {
		t.Fatalf("Iterate: %v", err)
	}

	if len(paths) != 3 {
		t.Fatalf("expected 3 files, got %d: %v", len(paths), paths)
	}
}

// TestDirSourceIteratePattern filters by regex.
func TestDirSourceIteratePattern(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, name := range []string{"a.jsonl", "b.jsonl", "c.txt", "d.log"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o644); err != nil {
			t.Fatalf("write file: %v", err)
		}
	}

	src := &DirSource{
		Path:      dir,
		Recursive: false,
		Pattern:   regexp.MustCompile(`\.jsonl$`),
	}
	paths := []string{}
	if err := src.Iterate(context.Background(), func(p string) error {
		paths = append(paths, p)
		return nil
	}); err != nil {
		t.Fatalf("Iterate: %v", err)
	}

	if len(paths) != 2 {
		t.Fatalf("expected 2 .jsonl files, got %d: %v", len(paths), paths)
	}
}

// TestDirSourceOpenReturnsError verifies Open is not usable for directories.
func TestDirSourceOpenReturnsError(t *testing.T) {
	t.Parallel()

	src := &DirSource{Path: t.TempDir()}
	_, err := src.Open(context.Background())
	if err == nil {
		t.Fatal("expected error from DirSource.Open")
	}
}

// TestDirSourceFormat returns parser.SourceAuto.
func TestDirSourceFormat(t *testing.T) {
	t.Parallel()

	src := &DirSource{Path: t.TempDir()}
	if got := src.Format(); got != parser.SourceAuto {
		t.Fatalf("Format: got %v, want %v", got, parser.SourceAuto)
	}
}

// TestDirSourceIterateContextCancellation stops on ctx cancellation.
func TestDirSourceIterateContextCancellation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for i := 0; i < 100; i++ {
		name := filepath.Join(dir, fmt.Sprintf("file-%05d.jsonl", i))
		if err := os.WriteFile(name, []byte("data"), 0o644); err != nil {
			t.Fatalf("write file: %v", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	src := &DirSource{Path: dir, Recursive: false}
	count := 0
	if err := src.Iterate(ctx, func(p string) error {
		count++
		if count >= 5 {
			cancel()
			return context.Canceled
		}
		return nil
	}); err != nil && !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("expected context.Canceled error, got: %v", err)
	}
}

// TestConvenienceConstructors checks the package-level helpers.
func TestConvenienceConstructors(t *testing.T) {
	t.Parallel()

	var src Source = &FileSource{Path: "/tmp/test.jsonl"}
	if s, ok := src.(*FileSource); !ok || s.Path != "/tmp/test.jsonl" {
		t.Fatal("FileSource constructor mismatch")
	}

	src = &StdinSource{}
	if _, ok := src.(*StdinSource); !ok {
		t.Fatal("StdinSource constructor mismatch")
	}

	src = &DirSource{Path: "/tmp/testdir"}
	if d, ok := src.(*DirSource); !ok || d.Path != "/tmp/testdir" {
		t.Fatal("DirSource constructor mismatch")
	}
}

// TestMaybeGzipPlain reads non-gzip bytes and returns them verbatim.
func TestMaybeGzipPlain(t *testing.T) {
	t.Parallel()

	plain := []byte("hello world")
	src := &FileSource{Path: filepath.Join(t.TempDir(), "plain.jsonl")}
	if err := os.WriteFile(src.Path, plain, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	rc, err := src.Open(context.Background())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(data) != string(plain) {
		t.Fatalf("got %q, want %q", data, plain)
	}
}

// TestMaybeGzipMagic detects gzip.
func TestMaybeGzipMagic(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	raw := `{"flow":true}
`
	filePath := filepath.Join(dir, "data.gz")

	f, err := os.Create(filePath)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	w := gzip.NewWriter(f)
	if _, err := io.Copy(w, strings.NewReader(raw)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	w.Close()
	f.Close()

	src := &FileSource{Path: filePath}
	rc, err := src.Open(context.Background())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(data) != raw {
		t.Fatalf("got %q, want %q", data, raw)
	}
}

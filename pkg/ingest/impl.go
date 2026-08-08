package ingest

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/flowguarder/flowguarder/pkg/parser"
)

// FileSource implements Source for a single file on disk.
type FileSource struct {
	Path        string
	Compression Compression
}

// Open opens the file and returns an io.ReadCloser. Magic-byte detection
// auto-decompresses gzip (0x1f 0x8b) when Compression is None (default).
func (s *FileSource) Open(_ context.Context) (io.ReadCloser, error) {
	if s.Path == "" {
		return nil, fmt.Errorf("ingest: FileSource.Open: path is empty")
	}
	f, err := os.Open(s.Path)
	if err != nil {
		return nil, err
	}
	var reader io.Reader = f
	if s.Compression == None {
		reader, err = maybeGzip(f)
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("ingest: %w", err)
		}
	}
	return fileReader{rc: f, r: reader}, nil
}

// Format returns parser.SourceAuto so downstream parsers auto-detect.
func (s *FileSource) Format() parser.Source {
	return parser.SourceAuto
}

// Ensure compile-time compliance.
var _ Source = (*FileSource)(nil)

// StdinSource implements Source for os.Stdin.
type StdinSource struct{}

// Open returns an io.ReadCloser wrapping os.Stdin. Close is a no-op.
func (s *StdinSource) Open(_ context.Context) (io.ReadCloser, error) {
	return stdinRC{}, nil
}

// Format returns parser.SourceAuto.
func (s *StdinSource) Format() parser.Source {
	return parser.SourceAuto
}

// Ensure compile-time compliance.
var _ Source = (*StdinSource)(nil)

// DirSource iterates over files in a directory.
type DirSource struct {
	Path      string
	Recursive bool
	Pattern   *regexp.Regexp
}

// Open always returns an error — directories are not single streams.
func (s *DirSource) Open(_ context.Context) (io.ReadCloser, error) {
	return nil, fmt.Errorf("ingest: DirSource.Open: use Iterate for directories")
}

// Format returns parser.SourceAuto.
func (s *DirSource) Format() parser.Source {
	return parser.SourceAuto
}

// Ensure compile-time compliance.
var _ Source = (*DirSource)(nil)

// Iterate walks the directory (optionally recursively) and calls fn for each
// file whose name matches the Pattern regex. Files are visited in
// lexicographic order for determinism.
func (s *DirSource) Iterate(ctx context.Context, fn func(path string) error) error {
	fullpath := s.Path
	if !strings.HasSuffix(fullpath, "/") {
		fullpath = fullpath + "/"
	}

	if !s.Recursive {
		entries, err := os.ReadDir(s.Path)
		if err != nil {
			return err
		}
		for _, e := range entries {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if e.IsDir() {
				continue
			}
			if s.Pattern != nil && !s.Pattern.MatchString(e.Name()) {
				continue
			}
			if err := fn(fullpath + e.Name()); err != nil {
				return err
			}
		}
		return nil
	}

	return filepath.WalkDir(s.Path, func(path string, d os.DirEntry, err error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if s.Pattern != nil && !s.Pattern.MatchString(d.Name()) {
			return nil
		}
		return fn(path)
	})
}

// SourceFilePattern is a helper to compile a regex pattern for DirSource.
func SourceFilePattern(p string) (*regexp.Regexp, error) {
	return regexp.Compile(p)
}

// fileReader wraps an *os.File and a logical body reader.
type fileReader struct {
	rc *os.File
	r  io.Reader
}

func (f fileReader) Read(p []byte) (int, error) { return f.r.Read(p) }
func (f fileReader) Close() error               { return f.rc.Close() }

// stdinRC provides io.ReaderCloser wrapping os.Stdin. Close is a no-op.
type stdinRC struct{}

func (stdinRC) Read(p []byte) (int, error) { return os.Stdin.Read(p) }
func (stdinRC) Close() error               { return nil }

// Ensure compile-time compliance.

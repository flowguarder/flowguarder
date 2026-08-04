package ingest

import (
	"context"
	"errors"
	"io"

	"github.com/flowguarder/flowguarder/pkg/parser"
)

// ErrAlreadyOpen indicates that the source is already open and cannot be
// reopened without first closing.
var ErrAlreadyOpen = errors.New("ingest: source already open")

// Compression denotes the compression encoding of a data stream.
type Compression int

const (
	// None indicates no compression.
	None Compression = iota
	// Gzip indicates gzip-compressed data; the reader will transparently
	// decompress before delivering records.
	Gzip
)

// Source is the interface that all flow input sources must implement. A Source
// produces an io.ReadCloser for reading structured flow data (typically JSON
// lines). Concrete implementations cover stdin, local files, directories, and
// live gRPC streams.
type Source interface {
	// Open returns a ReadCloser that yields the flow data stream. Open must be
	// called at most once per Source instance; subsequent calls must return
	// ErrAlreadyOpen. The caller is responsible for closing the returned reader
	// after use.
	Open(ctx context.Context) (io.ReadCloser, error)

	// Format returns the source's logical type, used by downstream parsers to
	// select the correct parsing strategy.
	Format() parser.Source
}

// NewFileSource returns a Source that reads from a single file.
func NewFileSource(path string) Source {
	return &FileSource{Path: path}
}

// NewStdinSource returns a Source that reads from standard input.
func NewStdinSource() Source {
	return &StdinSource{}
}

// NewDirSource returns a Source that iterates over all matching files in dir.
// Use DirSource.Iterate for iterating; Open always returns an error.
func NewDirSource(dir string) Source {
	return &DirSource{Path: dir}
}

package ingest

import (
	"bufio"
	"compress/gzip"
	"io"
)

// sniffSize is the number of bytes to peek for magic-byte detection.
const sniffSize = 2

// gzipMagic are the first two bytes of a gzip stream (RFC 1952).
var gzipMagic = []byte{0x1f, 0x8b}

// maybeGzip peeks the first two bytes of r and returns:
//   - a decompressing gzip.Reader when magic bytes match, or
//   - a TeeReader that prepends the two bytes back when they do not.
func maybeGzip(r io.Reader) (io.Reader, error) {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(r)
	}

	sniff := make([]byte, sniffSize)
	if _, err := io.ReadFull(br, sniff); err != nil {
		return nil, err
	}

	if sniff[0] == gzipMagic[0] && sniff[1] == gzipMagic[1] {
		gr, err := gzip.NewReader(&teeBackReader{br: br, buf: sniff})
		if err != nil {
			return nil, err
		}
		return gr, nil
	}

	// Non-gzip: push the sniffed bytes back via TeeReader.
	return &teeBackReader{br: br, buf: sniff}, nil
}

// teeBackReader wraps a bufio.Reader and prepends sniffed bytes.
type teeBackReader struct {
	br  *bufio.Reader
	buf []byte
}

func (t *teeBackReader) Read(p []byte) (int, error) {
	n := 0
	if len(t.buf) > 0 {
		n = copy(p, t.buf)
		t.buf = t.buf[n:]
	}
	nn, err := t.br.Read(p[n:])
	return n + nn, err
}

// Command validate-hubble parses a Hubble JSON-lines file using the same
// parser the CLI uses (pkg/parser/hubble), but first blank-imports the
// subpackage to populate the registry — mirroring the missing registration
// in cmd/flowguarder. This proves the fixture itself is well-formed.
package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/flowguarder/flowguarder/pkg/flow"
	"github.com/flowguarder/flowguarder/pkg/ingest"
	"github.com/flowguarder/flowguarder/pkg/parser"
	_ "github.com/flowguarder/flowguarder/pkg/parser/hubble"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: validate-hubble <file>")
		os.Exit(1)
	}

	src := ingest.NewFileSource(os.Args[1])
	r, err := src.Open(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "open: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = r.Close() }()

	p, err := parser.SelectParser(parser.SourceHubble, parser.SourceHubble)
	if err != nil {
		fmt.Fprintf(os.Stderr, "select: %v\n", err)
		os.Exit(1)
	}

	var parsed, invalid int
	err = p.Parse(r, func(f flow.Flow) error {
		if vErr := f.Validate(); vErr != nil {
			invalid++
			return nil
		}
		parsed++
		return nil
	})
	if err != nil && err != io.EOF {
		fmt.Fprintf(os.Stderr, "parse: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("parsed=%d invalid=%d\n", parsed, invalid)
}

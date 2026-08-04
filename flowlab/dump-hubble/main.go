// Command dump-hubble connects to a Hubble Relay gRPC server and writes
// raw GetFlows responses as JSON-lines to stdout. It runs for a configurable
// duration (default 3m) and is used to capture a fixture for offline
// analysis with `flowguarder analyze`.
//
// This is a standalone helper under flowlab/ — not part of the main CLI —
// because flowguarder itself does not provide raw-stream dumping.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	observer "github.com/cilium/cilium/api/v1/observer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
)

func main() {
	addr := flag.String("addr", "192.168.107.3:30425", "Hubble Relay gRPC address host:port")
	dur := flag.Duration("duration", 3*time.Minute, "how long to capture before exiting")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	ctx, stop := context.WithTimeout(ctx, *dur)
	defer stop()

	var dialOpts []grpc.DialOption
	dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))

	conn, err := grpc.NewClient(*addr, dialOpts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial %s: %v\n", *addr, err)
		os.Exit(1)
	}
	defer conn.Close()

	client := observer.NewObserverClient(conn)

	req := &observer.GetFlowsRequest{}

	stream, err := client.GetFlows(ctx, req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "GetFlows: %v\n", err)
		os.Exit(1)
	}

	log := slog.Default().With("cmd", "dump-hubble", "addr", *addr, "duration", dur.String())
	log.Info("capturing flows")

	opts := protojson.MarshalOptions{
		UseProtoNames:   true,
		EmitUnpopulated: true,
	}
	var count int
	for {
		resp, err := stream.Recv()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			fmt.Fprintf(os.Stderr, "recv: %v\n", err)
			break
		}
		fl := resp.GetFlow()
		if fl == nil {
			continue
		}
		data, err := opts.Marshal(fl)
		if err != nil {
			fmt.Fprintf(os.Stderr, "marshal: %v\n", err)
			continue
		}
		if _, err := os.Stdout.Write(data); err != nil {
			fmt.Fprintf(os.Stderr, "write: %v\n", err)
			break
		}
		if _, err := os.Stdout.Write([]byte("\n")); err != nil {
			break
		}
		count++
	}
	log.Info("done", "flows", count)
}

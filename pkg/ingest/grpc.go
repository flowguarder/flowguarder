package ingest

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	observer "github.com/cilium/cilium/api/v1/observer"
	"github.com/flowguarder/flowguarder/pkg/parser"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// HubbleGRPCClient is an ingest.Source that connects to a Hubble Relay
// gRPC server and streams GetFlows responses. It marshals each received
// proto.Flow to its canonical JSON representation so downstream consumers
// can plug into the existing JSON parser.
type HubbleGRPCClient struct {
	// Address is the gRPC address of the Hubble Relay endpoint
	// (e.g. "127.0.0.1:4245" or "hubble-relay.hubble.svc:443").
	Address string
	// Since limits the returned flows to those observed since this time.
	// Format: RFC 3339 string or Go Duration string (e.g. "10m", "30s",
	// "2024-01-15T10:30:00Z").
	Since string
	// TLS enables TLS for the gRPC connection.
	TLS bool
	// InsecureSkipVerify makes TLS accept any certificate presented by the
	// server regardless of host name.
	InsecureSkipVerify bool
}

// Ensure compile-time compliance.
var _ Source = (*HubbleGRPCClient)(nil)

// Format returns parser.SourceHubble so downstream parsers select the
// Hubble JSON parser.
func (c *HubbleGRPCClient) Format() parser.Source {
	return parser.SourceHubble
}

// parseSince converts the Since string into a *timestamppb.Timestamp.
// Duration strings like "10m" are interpreted relative to now; a full RFC 3339
// datetime string is parsed directly. An empty string returns nil (no limit).
func parseSince(s string) (*timestamppb.Timestamp, error) {
	if s == "" {
		return nil, nil
	}
	// Try parsing as a Duration string first.
	d, de := time.ParseDuration(s)
	if de == nil {
		return timestamppb.New(time.Now().Add(-d)), nil
	}
	// Fall back to RFC 3339.
	t, te := time.Parse(time.RFC3339, s)
	if te == nil {
		return nil, fmt.Errorf("ingest: invalid Since %q: not a duration or RFC 3339", s)
	}
	return timestamppb.New(t), nil
}

// Open connects to the configured Hubble Relay gRPC server and starts a
// GetFlows stream. It returns an io.ReadCloser whose Read method serializes
// each received flow as a single JSON line (protojson with UseProtoNames).
//
// The stream is drained in a background goroutine. It is cancelled when the
// caller closes the reader.
func (c *HubbleGRPCClient) Open(ctx context.Context) (io.ReadCloser, error) {
	if c.Address == "" {
		return nil, fmt.Errorf("ingest: HubbleGRPCClient.Open: Address is empty")
	}

	var dialOpts []grpc.DialOption
	if c.TLS {
		var creds credentials.TransportCredentials
		if c.InsecureSkipVerify {
			creds = insecure.NewCredentials()
		} else {
			creds = credentials.NewTLS(nil)
		}
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(creds))
	} else {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.NewClient(c.Address, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("ingest: HubbleGRPCClient.Open: dial %s: %w", c.Address, err)
	}

	client := observer.NewObserverClient(conn)

	var req *observer.GetFlowsRequest
	if s := c.Since; s != "" {
		ts, tsErr := parseSince(s)
		if tsErr != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("ingest: HubbleGRPCClient.Open: %w", tsErr)
		}
		req = &observer.GetFlowsRequest{Since: ts}
	} else {
		req = &observer.GetFlowsRequest{}
	}

	stream, err := client.GetFlows(ctx, req)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ingest: HubbleGRPCClient.Open: GetFlows: %w", err)
	}

	r := &grpcStreamReader{
		ctx:    ctx,
		conn:   conn,
		client: client,
		stream: stream,
		buf:    make(chan []byte, 128),
		done:   make(chan struct{}),
	}
	go r.loop()
	return r, nil
}

// grpcStreamReader drains a gRPC observer stream in a background goroutine
// and exposes it as an io.ReadCloser yielding JSON-lines, one flow per call
// to Read.
type grpcStreamReader struct {
	ctx    context.Context
	conn   *grpc.ClientConn
	client observer.ObserverClient
	stream observer.Observer_GetFlowsClient

	buf       chan []byte
	done      chan struct{}
	closeOnce sync.Once // idempotent close of conn + done + buf
	mu        sync.Mutex
	last      []byte
	err       error
}

// Read blocks until a single JSON line (one flow record) is available.
// Returns io.EOF when the stream is exhausted or closed.
func (r *grpcStreamReader) Read(p []byte) (int, error) {
	for {
		r.mu.Lock()
		if len(r.last) > 0 {
			n := copy(p, r.last)
			r.last = r.last[n:]
			r.mu.Unlock()
			return n, nil
		}
		r.mu.Unlock()

		select {
		case <-r.done:
			return 0, r.err
		case line, ok := <-r.buf:
			if !ok {
				return 0, io.EOF
			}
			if line == nil {
				return 0, io.EOF
			}
			n := copy(p, line)
			r.mu.Lock()
			if n < len(line) {
				r.last = line[n:]
			}
			r.mu.Unlock()
			return n, nil
		}
	}
}

// Close cancels the stream and closes the gRPC connection. Idempotent via
// sync.Once — safe to call concurrently with the loop's own deferred close.
func (r *grpcStreamReader) Close() error {
	var finalErr error
	r.closeOnce.Do(func() {
		close(r.done)
		finalErr = r.conn.Close()
	})
	return finalErr
}

// loop drains the gRPC stream in the background, marshaling each received
// proto.Flow to JSON and sending it to the buf channel. It sends nil on the
// channel when the stream is exhausted to signal EOF readers.
func (r *grpcStreamReader) loop() {
	log := slog.Default().With("source", "hubble-grpc")
	defer func() {
		// Idempotent close: Close() may already have closed these channels
		// via sync.Once above. closeOnce ensures exactly-once semantics.
		r.closeOnce.Do(func() {
			close(r.buf)
			close(r.done)
		})
	}()
	for {
		resp, err := r.stream.Recv()
		if err != nil {
			r.mu.Lock()
			r.err = fmt.Errorf("ingest: hubble-grpc recv: %w", err)
			r.mu.Unlock()
			log.Error(r.err.Error())
			return
		}
		if fl := resp.GetFlow(); fl != nil {
			data, merr := jsonOpts.Marshal(fl)
			if merr != nil {
				r.mu.Lock()
				if r.err == nil {
					r.err = fmt.Errorf("ingest: marshal flow: %w", merr)
				}
				r.mu.Unlock()
				log.ErrorContext(r.ctx, "marshal flow", "err", merr)
				return
			}
			// Send nil to signal EOF when context is cancelled.
			// Append a newline so the downstream JSON-lines parser can
			// split one flow per line even if the gRPC stream batches
			// multiple messages back-to-back.
			data = append(data, '\n')
			select {
			case <-r.ctx.Done():
				r.mu.Lock()
				r.err = r.ctx.Err()
				r.mu.Unlock()
				return
			case r.buf <- data:
			}
		}
	}
}

// marshalProto marshals protoMsg to a JSON line.
var jsonOpts = protojson.MarshalOptions{
	UseProtoNames:   true,
	EmitUnpopulated: false,
}

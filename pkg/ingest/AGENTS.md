# INGEST PACKAGE — `pkg/ingest`

## OVERVIEW
Concrete `Source` implementations: local files (auto-gzip), stdin, directories, and live Hubble gRPC streams.

## WHERE TO LOOK
| Task | File |
|---|---|
| Add new data source | `impl.go` (add struct, implement `Source`) |
| Modify gRPC client | `grpc.go` (`HubbleGRPCClient`, `parseSince`, `grpcStreamReader`) |
| Change gzip detection logic | `compress.go` (`maybeGzip`, `teeBackReader`) |
| Change directory iteration | `impl.go` (`DirSource.Iterate`, `SourceFilePattern`) |
| Define source format enum | `pkg/parser/parser.go` (`parser.Source`) — `ingest` only consumes |

## CONVENTIONS
- `Source.Open(ctx)` returns `io.ReadCloser`; callers must close it. Calling `Open` more than once on the same instance returns `ErrAlreadyOpen` (except `DirSource` — see below).
- `Source.Format()` returns a `parser.Source` value. `FileSource`, `StdinSource`, `DirSource` all return `parser.SourceAuto`; `HubbleGRPCClient` returns `parser.SourceHubble`.
- `FileSource.Compression == None` (default) triggers `maybeGzip` magic-byte peek (`0x1f 0x8b`) on `Open`; if `Compression == Gzip`, the caller must pre-decompress and set `Gzip`.
- `DirSource.Open` always returns an error. Use `DirSource.Iterate(ctx, fn)` for directory walks. `Iterate` visits files in lexicographic order; respects `Recursive` and optional `Pattern` regex.
- `HubbleGRPCClient` starts a background goroutine that drains the gRPC `GetFlows` stream into a buffered channel (`buf` capacity 128). `Close` cancels the stream and the goroutine.

## ANTI-PATTERNS
- Do NOT call `DirSource.Open` — it always errors. Use `Iterate` instead.
- Do NOT bypass the `maybeGzip` magic-byte peek in `FileSource.Open` — auto-detection is the default behavior. Only skip it by setting `Compression = Gzip` explicitly.
- Do NOT block on `os.Stdin` outside `StdinSource`.
- Do NOT couple `Source` to a specific parser — `Format()` returns an enum; parsing strategy lives in `pkg/parser`.
- Do NOT require a `kubeconfig` or external cluster access — `ingest` is offline-first. `HubbleGRPCClient` connects to an address string, not a config file.

## NOTES
- `grpc.go` has no tests. `HubbleGRPCClient` internals (`parseSince`, background stream draining, `protojson` marshaling) are untested.
- `ingest_test.go` is minimal — only a compile-time interface compliance check.
- `file_test.go` is thorough — covers `FileSource`, `DirSource`, `StdinSource`, `maybeGzip`, and pattern matching.
- `teeBackReader` in `compress.go` is a tiny untested helper that pushes sniffed bytes back into the read stream so the decompressor and consumer both see them intact.

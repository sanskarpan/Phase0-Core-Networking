# Fix & Enhancement Checklist

## 🔴 CORRECTNESS — Bugs in existing code

- [x] B1: `tcp/tcp.go` — `ConnectionPool.Put()` never decrements `activeConn` on the success path; counter grows unbounded and eventually starves all `Get()` calls.
- [x] B2: `tcp/tcp.go` — Pool liveness probe reads 1 byte from the connection to test for EOF; if data is pending it silently discards that byte, corrupting the application stream.
- [x] B3: `http/http.go` — HTTP client retry sends an empty body on POST/PUT; `bodyReader` is a `bytes.NewReader` that is at EOF after the first attempt and is never re-seeked.
- [x] B4: `rpc/rpc.go` — `serverStream.Context()` always returns `context.Background()`, ignoring the client deadline stored in `Message.Deadline`; stream handlers cannot respect per-call timeouts.
- [x] B5: `websocket/websocket.go` — `ReadMessage` has no maximum message size; a peer can send a frame header claiming 2^63 bytes, causing OOM.
- [x] B6: `security/auth.go` — `SessionManager.Get()` writes to `session.ExpiresAt` while holding only a read lock, creating a data race with concurrent readers and the cleanup goroutine.
- [x] B7: `http/http.go` — Rate limiter extracts client IP with `strings.Split(RemoteAddr, ":")[0]`, which yields `[` for IPv6 addresses like `[::1]:1234`; all IPv6 clients collapse to one bucket. Fix with `net.SplitHostPort`.
- [x] B8: `udp/udp.go` — `ReliableUDP.readLoop()` runs forever with no stop mechanism; every `NewReliableUDP` call leaks a goroutine permanently.
- [x] B9: `utils/utils.go` — `DNSResolver.startEviction()` goroutine runs forever; the `done` channel exists but is never closed because there is no `Close()` method on `DNSResolver`.
- [x] B10: `security/auth.go` — `SessionManager.cleanupLoop()` goroutine runs forever with no stop channel; every `NewSessionManager` call leaks a goroutine.
- [x] B11: `http/http.go` — `StartH2C()` and `StartTLS()` pass `s.router` directly to `http.Server`, bypassing all middleware registered via `Use()` (auth, rate-limiting, logging all silently skipped).
- [x] B12: `rpc/rpc.go` — `Server.requestCounter` is declared and exposed by `GetStats()` but is never incremented in any handler path; always returns 0.
- [x] B13: `tcp/tcp.go` — `Server.BytesReceived` and `BytesSent` are declared and returned by `GetStats()` but are never incremented; always return 0.

## 🟠 RESOURCE LEAKS — Goroutines that never stop

- [x] L1: `udp/udp.go` — `ReliableUDP` has no `Close()` method; `readLoop` goroutine leaks on every instance. Add `Close()` + `done` channel. (Overlaps B8 — resolve together.)
- [x] L2: `utils/utils.go` — `DNSResolver` has no `Close()` method; `startEviction` goroutine leaks. Add `Close()` method that closes the `done` channel. (Overlaps B9.)
- [x] L3: `security/auth.go` — `SessionManager` has no `Close()` method; `cleanupLoop` goroutine leaks. Add `Close()` + `done` channel. (Overlaps B10.)
- [x] L4: `rpc/discovery.go` — `DiscoveryClient.Watch()` launches a goroutine with no cancellation mechanism; caller cannot stop it, leaking the goroutine and ticker. Add `ctx context.Context` parameter.
- [x] L5: `udp/udp.go` — `ReliableUDP.receivedSeqs` map is allocated but never read or written; deduplication of retransmitted packets was planned but never implemented. Implement dedup or remove the dead field.
- [x] L6: `security/auth.go` — `LoginTracker` cleanup goroutine has no stop mechanism; add `Close()` + `done` channel.

## 🟡 PRODUCTION HARDENING — Missing real-world safeguards

- [x] P1: `http/http.go` — No request body size limit; an unlimited POST body can exhaust server memory. Add `BodyLimit(maxBytes int64) Middleware` using `http.MaxBytesReader`.
- [x] P2: `metrics/metrics.go` + `http/http.go` — `HTTPMetrics.Middleware()` returns `func(http.Handler) http.Handler` but the HTTP server uses a custom `Middleware` type `func(Handler) Handler`; the two are type-incompatible so metrics are unreachable in practice. Add a bridge adapter and wire `TCPMetrics` into `tcp.Server`.
- [x] P3: `rpc/rpc.go` — No interceptor/middleware chain; no way to add cross-cutting concerns (auth, logging, rate-limiting, tracing) to RPC handlers without modifying each one. Add `UnaryInterceptor` and `StreamInterceptor` to `Server`.
- [x] P4: `tcp/tcp.go` — Server-accepted connections have no read/write deadline; a slow-loris attacker can hold connections open indefinitely. Add `IdleTimeout time.Duration` to `Server`; set it on each accepted conn.
- [x] P5: `websocket/websocket.go` — Client handshake reads HTTP upgrade response in a single `conn.Read(4096)` call; fails if response exceeds 4096 bytes or arrives in multiple TCP segments. Use `bufio.NewReader`.
- [x] P6: `websocket/websocket.go` — `WriteCompressedMessage` compresses with `compress/flate` but does not set the RSV1 bit (RFC 7692 §7.2.1); receiver cannot distinguish compressed from uncompressed frames.
- [x] P7: `tcp/tcp.go` — `ConnectionPool` stores `MaxIdleTime` but never enforces it; stale connections sit in the pool forever after the remote server has closed them. Add a background eviction goroutine.
- [x] P8: `rpc/rpc.go` — `Server.Stop()` closes the listener and waits on WaitGroup but does not signal active handlers; long-running calls are abruptly terminated. Add a context-based drain with timeout.
- [x] P9: `rpc/rpc.go` — After reconnect, old `pendingCalls` and `streamChans` entries reference the dead connection's readLoop and hang forever. On reconnect, fail all in-flight calls with an error.
- [x] P10: `tcp/tcp.go` — `KeepAliveConn` is missing `LocalAddr()`, `RemoteAddr()`, `SetDeadline()`, `SetReadDeadline()`, `SetWriteDeadline()`; it cannot be used as a `net.Conn` drop-in replacement.

## 🟢 OBSERVABILITY — Missing metrics & tracing

- [x] O1: `rpc/rpc.go` + `metrics/metrics.go` — No RPC metrics; add call count, latency histogram, and error-rate-by-method tracking. Expose via `metrics.NewRPCMetrics()`.
- [x] O2: `websocket/websocket.go` + `metrics/metrics.go` — No WebSocket metrics; add active-connection gauge, messages-per-second counter, and frame-size histogram. Expose via `metrics.NewWebSocketMetrics()`.
- [x] O3: `utils/utils.go` + `metrics/metrics.go` — No DNS metrics; add cache-hit-rate counter and resolution-latency histogram. Expose via `metrics.NewDNSMetrics()`.
- [x] O4: `tcp/tcp.go` + `metrics/metrics.go` — No circuit-breaker state metric; expose current state (0=Closed, 1=HalfOpen, 2=Open) and trip-count counter.
- [x] O5: `metrics/metrics.go` — `ServeMetrics` silently swallows the error from `http.ListenAndServe`; if the port is taken, it fails without any log message. Return or log the error.
- [x] O6: `metrics/metrics.go` — `MustRegister` panics on duplicate registration; using multiple instances of `NewHTTPMetrics` or `NewTCPMetrics` crashes the process. Support a custom `prometheus.Registerer` parameter.

## 🔵 COMPLETENESS — Integration & test gaps

- [x] C1: No integration test suite combining multiple packages (HTTP server + JWT middleware + TLS + metrics + rate-limiting end-to-end). Add `integration/integration_test.go`.
- [x] C2: `internal/framing/framing.go` — MaxFrameSize (10 MB) is hardcoded; no per-connection configurable limit and no test that oversized frames are actually rejected.
- [x] C3: `security/auth.go` — `OAuthProvider` generates refresh tokens but has no mechanism to validate or exchange them; the refresh token field is dead code. Implement a `RefreshToken(refreshToken string) (*OAuthToken, error)` method backed by an in-memory store.
- [x] C4: `security/tls.go` — `TLSServer` and `TLSClient` wrappers are never used by `tcp/`, `rpc/`, or `websocket/`; those packages accept raw `*tls.Config` directly, making the wrappers orphaned. Wire them in or document the intended usage.
- [x] C5: `utils/utils.go` — `LookupSRV` does not cache results despite the design intent; add TTL-based caching consistent with `LookupIP`.

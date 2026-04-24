# Features Tracker

## 🔴 CRITICAL (Safety / Correctness)

- [x] C1: All server goroutines (tcp, udp, http, rpc, websocket) — Add panic recovery
  with `recover()` + `slog.Error` so a panicking handler never silently kills a goroutine.

- [x] C2: tcp/tcp.go RequestResponseClient.SendRequest — Fix goroutine leak: the
  internal reader goroutine must respect context cancellation via `select { case
  <-ctx.Done(): }` and return, not block forever.

- [x] C3: rpc/rpc.go — Server handlers always use context.Background(). Thread the
  client's context (including deadline) through to every handler call so per-call
  timeouts are respected server-side.

- [x] C4: rpc/rpc.go Client.Call — On context cancellation during send, the pending
  channel is leaked. Add a deferred delete from pendingCalls and drain the channel on
  cancellation.

- [x] C5: rpc/discovery.go HTTPHealthChecker.Check — Currently does a TCP dial, not
  an HTTP request. Replace with a real `net/http.Get` with a timeout context; treat
  any 5xx or error as unhealthy.

- [x] C6: rpc/rpc.go LoadBalancedClient — `activeConns` is incremented on Call() but
  never decremented. Add `defer func() { atomic.AddInt64(&client.activeConns, -1) }()`
  at the start of every Call().

- [x] C7: websocket/websocket.go — Control frames (Ping, Pong, Close) MUST have FIN=1
  per RFC 6455 §5.5. Add validation in ReadFrame that returns an error if a control
  frame has FIN=0.

- [x] C8: security/auth.go JWT.Verify — NotBefore (`nbf`) claim is stored but not
  checked. Add: `if claims.NotBefore > 0 && time.Now().Unix() < claims.NotBefore {
  return error }`.

## 🟠 HIGH (Major Missing Features)

- [x] H1: TLS wiring — tcp/ — Add `func NewTLSServer(addr string, handler Handler,
  cfg *tls.Config) *Server` and `func (c *Client) DialTLS(addr string, cfg
  *tls.Config) error` using `crypto/tls`. Wire to existing `security/tls.go`.

- [x] H2: TLS wiring — rpc/ — Add TLS dial support to RPC Client (`DialTLS`) and TLS
  listener to RPC Server (`ListenTLS`). Use `tls.Listen` / `tls.Dial`.

- [x] H3: TLS wiring — websocket/ — Add `wss://` support to Client.Connect and
  Upgrader.Upgrade. Accept optional `*tls.Config`; if present, wrap the connection.

- [x] H4: HTTP/2 support — http/http.go — Add `func (s *Server) StartH2C() error`
  that serves HTTP/2 over cleartext using `golang.org/x/net/http2/h2c`. Add
  `func (s *Server) StartTLS(certFile, keyFile string) error` for H2 over TLS.
  Update go.mod.

- [x] H5: gzip middleware — http/http.go — Add `func GzipMiddleware() Middleware` that
  compresses responses with `compress/gzip` when the client sends
  `Accept-Encoding: gzip`. Use a `sync.Pool` for gzip writers.

- [x] H6: Request ID middleware — http/http.go — Add `func RequestIDMiddleware()
  Middleware` that generates a UUID (crypto/rand, formatted as hex), sets it as
  `X-Request-ID` response header, and injects it into the request context under a
  typed key `type requestIDKey struct{}`. Expose `GetRequestID(ctx) string` helper.

- [x] H7: JWT HTTP middleware — http/http.go — Add `func JWTMiddleware(j
  *security.JWT) Middleware` that extracts `Authorization: Bearer <token>`, calls
  `j.Verify()`, and rejects with 401 on failure. Import security package.

- [x] H8: API key HTTP middleware — http/http.go — Add `func
  APIKeyMiddleware(m *security.APIKeyManager) Middleware` that reads
  `X-API-Key` header, calls `m.Verify()`, rejects with 401 on failure.

- [x] H9: WebSocket close codes — websocket/websocket.go — Add `CloseCode uint16`
  and `CloseReason string` fields. Add `func (c *Conn) CloseWithCode(code uint16,
  reason string) error` that sends a proper Close frame per RFC 6455 §5.5.1.
  Standard codes: 1000 Normal, 1001 GoingAway, 1002 ProtocolError, 1011
  InternalError.

- [x] H10: WebSocket subprotocol negotiation — websocket/websocket.go — Add
  `Protocols []string` to Upgrader. During upgrade, intersect with client's
  `Sec-WebSocket-Protocol` header and set the negotiated protocol on `Conn`.
  Expose `conn.Protocol() string`.

- [x] H11: ChaCha20-Poly1305 — security/crypto.go — Add `ChaCha20Cipher` struct
  with `Encrypt(plaintext []byte) ([]byte, error)` and `Decrypt(ciphertext []byte)
  ([]byte, error)` using `golang.org/x/crypto/chacha20poly1305`. Update go.mod.

- [x] H12: Argon2id KDF — security/crypto.go — Add `func DeriveKeyArgon2(password,
  salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte` using
  `golang.org/x/crypto/argon2`. Prefer over PBKDF2 for new code.

- [x] H13: Key material zeroing — security/crypto.go — Add `func ZeroBytes(b []byte)`
  using `for i := range b { b[i] = 0 }` and call it in all places where key
  material (AES keys, RSA private key bytes) goes out of scope via defer.

- [x] H14: Prometheus metrics — Add new package `metrics/metrics.go` with:
  - `NewHTTPMetrics()` returning a middleware that records request count, duration
    histogram, and status code labels using `github.com/prometheus/client_golang`.
  - `NewTCPMetrics()` returning per-server gauges for active connections, bytes.
  - A `ServeMetrics(addr string)` function that starts a `/metrics` endpoint.
  Update go.mod.

- [x] H15: Weighted round-robin load balancer — utils/utils.go — Implement proper
  weighted round-robin in `LoadBalancer.GetBackend()` for `RoundRobin` strategy:
  expand the selection ring by replicating each backend `Weight` times. If Weight
  is 0 treat as 1.

- [x] H16: HTTP client redirect following — http/http.go — In `Client.doRequest()`,
  if the response status is 301/302/303/307/308, follow the `Location` header up to
  `MaxRedirects int` (default 10) hops. Detect redirect loops.

- [x] H17: HTTP pprof debug endpoint — http/http.go — Add `func (s *Server)
  RegisterPprof()` that registers `net/http/pprof` handlers under `/debug/pprof/`.

## 🟡 MEDIUM (Production Hardening)

- [x] M1: Graceful drain on shutdown — tcp/tcp.go Server.Stop — After closing the
  listener, call `s.wg.Wait()` with a configurable drain timeout (default 30s).
  If timeout expires, log a warning and force-close remaining connections. Currently
  `Stop()` returns before in-flight handlers finish.

- [x] M2: Max connections limit — tcp/tcp.go Server — Add `MaxConnections int` field
  (default 0 = unlimited). In acceptLoop, if `atomic.LoadInt64(&s.ActiveConnections)
  >= MaxConnections`, close the accepted conn immediately and increment a
  `RejectedConnections` counter.

- [x] M3: TCP_NODELAY — tcp/tcp.go — Call `conn.(*net.TCPConn).SetNoDelay(true)` on
  every accepted and dialed TCP connection unless `DisableNoDelay bool` is set on
  Server/Client.

- [x] M4: Circuit breaker — tcp/tcp.go ConnectionPool — Add a `CircuitBreaker` struct
  with states Closed/Open/HalfOpen. After `FailureThreshold` consecutive dial
  failures, open the circuit and reject Get() with ErrCircuitOpen. After
  `RecoveryTimeout`, try one probe connection (HalfOpen). On success, close again.

- [x] M5: Buffer pool — internal/framing/framing.go — Use `sync.Pool` for the 4-byte
  header buffer in `WriteFrame` and for the payload buffer in `ReadFrame` (capped
  at a reasonable size, e.g., 64KB; larger frames allocate fresh).

- [x] M6: RPC per-call timeout — rpc/rpc.go — Add `DefaultCallTimeout time.Duration`
  to Client (default 30s). In `Call()`, if ctx has no deadline, wrap it with
  `context.WithTimeout(ctx, c.DefaultCallTimeout)`.

- [x] M7: RPC structured error codes — rpc/rpc.go — Replace the string error in
  `RPCMessage` with `RPCError { Code int; Message string; Details map[string]any }`.
  Define standard codes: 0=OK, 1=Canceled, 2=Unknown, 4=DeadlineExceeded,
  5=NotFound, 13=Internal, 14=Unavailable.

- [x] M8: RPC stream demultiplexer — rpc/rpc.go — Replace direct conn reads in
  stream.Recv() with a per-stream channel populated by the single Client readLoop.
  Add a `streamChans map[uint64]chan *RPCMessage` protected by a mutex. The readLoop
  routes messages to the right channel by RequestID.

- [x] M9: Negative DNS caching — utils/utils.go DNSResolver — On a failed lookup,
  store a negative entry with a shorter TTL (default 10s) so repeated lookups for
  dead hostnames don't hit the network every time.

- [x] M10: SRV record lookup — utils/utils.go — Add `func (dr *DNSResolver)
  LookupSRV(service, proto, name string) ([]*net.SRV, error)` wrapping
  `net.DefaultResolver.LookupSRV`. Cache results with TTL.

- [x] M11: Weighted random load balancer — utils/utils.go — Add a `WeightedRandom`
  strategy to `LoadBalancer.GetBackend()`. Use cumulative weight selection with
  crypto/rand for unpredictable distribution.

- [x] M12: WebSocket permessage-deflate — websocket/websocket.go — Add
  `EnableCompression bool` to Upgrader and Conn. If negotiated, wrap the payload
  with `compress/flate` (RFC 7692). Add `Conn.WriteCompressedMessage()` as the
  opt-in entry point.

- [x] M13: Session security — security/auth.go SessionManager — Encrypt session Data
  with AES-256-GCM (using the existing `AESCipher`). Accept a `encryptionKey []byte`
  in `NewSessionManager`. Store only ciphertext in `session.Data`.

- [x] M14: Failed login lockout — security/auth.go — Add `LoginTracker` struct with
  `MaxAttempts int` (default 5) and `LockoutDuration time.Duration` (default 15min).
  `RecordFailure(userID string)` increments attempts; `IsLocked(userID string) bool`
  checks. Use atomic maps + periodic cleanup goroutine.

- [x] M15: Password pepper — security/auth.go PasswordHasher — Add `Pepper []byte`
  field. Before bcrypt hashing, HMAC-SHA256 the password with the pepper:
  `peppered := hmac.New(sha256.New, ph.Pepper); peppered.Write([]byte(password))`.
  Hash the hex-encoded result. Verify applies the same transformation.

## 🟢 LOW (Quality / Performance)

- [x] L1: HTTP trie router — http/http.go — Replace the flat `map[string]Handler` in
  Router with a radix trie that supports `:param` path parameters and `*wildcard`
  segments. Expose `GetParam(r *http.Request, name string) string` helper. Keep
  backward compatibility for exact paths.

- [x] L2: HTTP cookie jar — http/http.go Client — Add `CookieJar http.CookieJar`
  field. If non-nil, pass it to the underlying `http.Client`. Default to nil (no
  automatic cookie handling).

- [x] L3: HTTP CORS preflight — http/http.go CORSMiddleware — Properly handle OPTIONS
  preflight: respond with 204, set `Access-Control-Allow-Methods`,
  `Access-Control-Allow-Headers`, and `Access-Control-Max-Age`. Only allow methods
  and headers that are registered on the router.

- [x] L4: DNS IPv6 (AAAA) — utils/utils.go DNSResolver.LookupIP — Return both A and
  AAAA records. Separate them into `LookupIPv4` and `LookupIPv6` helpers. Update
  the cache to store per-family slices.

- [x] L5: framing CRC32 checksum — internal/framing/framing.go — Add an optional
  `WithChecksum bool` parameter via a `FramerOptions` struct. When enabled, append
  a 4-byte CRC32 (IEEE) to the frame before sending and verify it on read.

- [x] L6: RPC server reflection — rpc/rpc.go — Add a built-in `__reflection__` handler
  that returns a JSON list of all registered method names. Accessible via
  `client.ListMethods(ctx) ([]string, error)`.

- [x] L7: Health HTTP endpoint — http/http.go — Add `func (s *Server)
  RegisterHealthz()` that registers `/healthz` returning `{"status":"ok"}` and
  `/readyz` that returns 200 only after the server has been up for a configurable
  `ReadyDelay` (default 0). Useful for Kubernetes probes.

- [x] L8: pprof endpoint — already in H17, skip.

- [x] L9: UDPv6 — udp/udp.go — Add `Server.ListenIPv6(addr string) error` that
  binds `udp6` network. Multicast group join must also handle IPv6 multicast
  addresses (ff00::/8).

- [x] L10: PBKDF2 → Argon2 migration helper — security/crypto.go — Add
  `MigrateHash(oldPBKDF2Hash []byte, password string, newParams Argon2Params)
  ([]byte, error)` that verifies the old hash and, on success, re-derives with
  Argon2id.

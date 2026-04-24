/*
TCP Socket Programming
======================

Comprehensive TCP implementations including servers, clients, connection pooling, and utilities.

Applications:
- TCP server/client communication
- Connection pooling
- Keep-alive management
- Message framing
- Load balancing
*/

package tcp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Phase0_Core/Networking/internal/framing"
)

// =============================================================================
// TCP Server
// =============================================================================

// Handler processes incoming connections
type Handler func(conn net.Conn)

// Server represents a TCP server
type Server struct {
	Address         string
	Handler         Handler
	TLSConfig       *tls.Config
	DisableNoDelay  bool
	MaxConnections  int64
	DrainTimeout    time.Duration
	IdleTimeout     time.Duration // P4: set read deadline on each accepted conn
	listener        net.Listener
	done            chan struct{}
	wg              sync.WaitGroup
	mu              sync.Mutex
	active          bool

	// Statistics
	TotalConnections    int64
	ActiveConnections   int64
	BytesReceived       int64
	BytesSent           int64
	RejectedConnections int64
}

// trackingConn wraps net.Conn to track bytes sent/received in the server stats. (B13)
type trackingConn struct {
	net.Conn
	server *Server
}

func (tc *trackingConn) Read(b []byte) (int, error) {
	n, err := tc.Conn.Read(b)
	if n > 0 {
		atomic.AddInt64(&tc.server.BytesReceived, int64(n))
	}
	return n, err
}

func (tc *trackingConn) Write(b []byte) (int, error) {
	n, err := tc.Conn.Write(b)
	if n > 0 {
		atomic.AddInt64(&tc.server.BytesSent, int64(n))
	}
	return n, err
}

// NewServer creates a new TCP server
func NewServer(address string, handler Handler) *Server {
	return &Server{
		Address: address,
		Handler: handler,
		done:    make(chan struct{}),
	}
}

// NewTLSServer creates a TCP server that uses TLS for all connections.
func NewTLSServer(addr string, handler Handler, cfg *tls.Config) *Server {
	s := NewServer(addr, handler)
	s.TLSConfig = cfg
	return s
}

// Start starts the TCP server
func (s *Server) Start() error {
	s.mu.Lock()
	if s.active {
		s.mu.Unlock()
		return errors.New("server already running")
	}

	var listener net.Listener
	var err error
	if s.TLSConfig != nil {
		listener, err = tls.Listen("tcp", s.Address, s.TLSConfig)
	} else {
		listener, err = net.Listen("tcp", s.Address)
	}
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to start server: %w", err)
	}

	s.listener = listener
	s.active = true
	s.done = make(chan struct{})
	s.mu.Unlock()

	s.wg.Add(1)
	go s.acceptLoop()

	return nil
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				continue
			}
		}

		// M2: Max connections limit
		if s.MaxConnections > 0 && atomic.LoadInt64(&s.ActiveConnections) >= s.MaxConnections {
			conn.Close()
			atomic.AddInt64(&s.RejectedConnections, 1)
			continue
		}

		atomic.AddInt64(&s.TotalConnections, 1)
		atomic.AddInt64(&s.ActiveConnections, 1)

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()
	defer atomic.AddInt64(&s.ActiveConnections, -1)

	// C1: Panic recovery
	defer func() {
		if r := recover(); r != nil {
			slog.Error("tcp: panic in handler", "err", r)
		}
	}()

	// M3: TCP_NODELAY
	if !s.DisableNoDelay {
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.SetNoDelay(true)
		}
	}

	// P4: Set read deadline to prevent slow-loris attacks
	if s.IdleTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(s.IdleTimeout))
	}

	// B13: Wrap with tracking conn to count bytes
	s.Handler(&trackingConn{Conn: conn, server: s})
}

// Stop stops the TCP server
func (s *Server) Stop() error {
	s.mu.Lock()
	if !s.active {
		s.mu.Unlock()
		return errors.New("server not running")
	}

	close(s.done)
	s.listener.Close()
	s.active = false
	s.mu.Unlock()

	// M1: Graceful drain with timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	timeout := s.DrainTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	select {
	case <-done:
	case <-time.After(timeout):
		slog.Warn("tcp: drain timeout exceeded, forcing shutdown")
	}
	return nil
}

// GetStats returns server statistics
func (s *Server) GetStats() (total, active, bytesRx, bytesTx int64) {
	return atomic.LoadInt64(&s.TotalConnections),
		atomic.LoadInt64(&s.ActiveConnections),
		atomic.LoadInt64(&s.BytesReceived),
		atomic.LoadInt64(&s.BytesSent)
}

// IsActive returns whether the server is currently active
func (s *Server) IsActive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

// GetListener returns the underlying listener
func (s *Server) GetListener() net.Listener {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listener
}

// =============================================================================
// TCP Client
// =============================================================================

// Client represents a TCP client
type Client struct {
	Address        string
	Timeout        time.Duration
	DisableNoDelay bool
	conn           net.Conn
	mu             sync.Mutex
}

// NewClient creates a new TCP client
func NewClient(address string, timeout time.Duration) *Client {
	return &Client{
		Address: address,
		Timeout: timeout,
	}
}

// Connect establishes connection to server
func (c *Client) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		return errors.New("already connected")
	}

	conn, err := net.DialTimeout("tcp", c.Address, c.Timeout)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}

	// M3: TCP_NODELAY
	if !c.DisableNoDelay {
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.SetNoDelay(true)
		}
	}

	c.conn = conn
	return nil
}

// DialTLS connects to a TLS server.
func (c *Client) DialTLS(addr string, cfg *tls.Config) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return errors.New("already connected")
	}
	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		return fmt.Errorf("TLS dial failed: %w", err)
	}
	// M3: TCP_NODELAY on underlying TCP connection
	if !c.DisableNoDelay {
		if tc, ok := conn.NetConn().(*net.TCPConn); ok {
			tc.SetNoDelay(true)
		}
	}
	c.conn = conn
	return nil
}

// Send sends data to server
func (c *Client) Send(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return errors.New("not connected")
	}

	if c.Timeout > 0 {
		c.conn.SetWriteDeadline(time.Now().Add(c.Timeout))
	}

	_, err := c.conn.Write(data)
	return err
}

// Receive receives data from server
func (c *Client) Receive(buffer []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return 0, errors.New("not connected")
	}

	if c.Timeout > 0 {
		c.conn.SetReadDeadline(time.Now().Add(c.Timeout))
	}

	return c.conn.Read(buffer)
}

// Close closes the connection
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil
	}

	err := c.conn.Close()
	c.conn = nil
	return err
}

// =============================================================================
// Connection Pool
// =============================================================================

// PoolConfig configures connection pool
type PoolConfig struct {
	MaxConnections int
	MinConnections int
	MaxIdleTime    time.Duration
	DialTimeout    time.Duration
}

// pooledConn wraps a net.Conn with an idle timestamp for MaxIdleTime enforcement.
type pooledConn struct {
	conn   net.Conn
	pooled time.Time
}

// ConnectionPool manages a pool of TCP connections
type ConnectionPool struct {
	address    string
	config     PoolConfig
	pool       chan *pooledConn
	factory    func() (net.Conn, error)
	mu         sync.Mutex
	closed     bool
	activeConn int64
	CB         *CircuitBreaker
	done       chan struct{}
}

// NewConnectionPool creates a connection pool
func NewConnectionPool(address string, config PoolConfig) (*ConnectionPool, error) {
	if config.MaxConnections <= 0 {
		config.MaxConnections = 10
	}
	if config.MinConnections < 0 {
		config.MinConnections = 0
	}

	pool := &ConnectionPool{
		address: address,
		config:  config,
		pool:    make(chan *pooledConn, config.MaxConnections),
		factory: func() (net.Conn, error) {
			return net.DialTimeout("tcp", address, config.DialTimeout)
		},
		done: make(chan struct{}),
	}

	// Pre-create minimum connections
	for i := 0; i < config.MinConnections; i++ {
		conn, err := pool.factory()
		if err != nil {
			return nil, fmt.Errorf("failed to create initial connection: %w", err)
		}
		pool.pool <- &pooledConn{conn: conn, pooled: time.Now()}
	}

	// P7: Start background eviction goroutine to enforce MaxIdleTime
	if config.MaxIdleTime > 0 {
		go pool.evictLoop()
	}

	return pool, nil
}

// evictLoop drains connections that have been idle longer than MaxIdleTime.
func (cp *ConnectionPool) evictLoop() {
	ticker := time.NewTicker(cp.config.MaxIdleTime / 2)
	defer ticker.Stop()
	for {
		select {
		case <-cp.done:
			return
		case <-ticker.C:
			// Drain and re-enqueue connections that are still fresh
			var fresh []*pooledConn
			for {
				select {
				case pc := <-cp.pool:
					if time.Since(pc.pooled) < cp.config.MaxIdleTime {
						fresh = append(fresh, pc)
					} else {
						pc.conn.Close()
					}
				default:
					goto done
				}
			}
		done:
			for _, pc := range fresh {
				select {
				case cp.pool <- pc:
				default:
					// Pool full, close excess
					pc.conn.Close()
				}
			}
		}
	}
}

// Get retrieves a connection from the pool
func (cp *ConnectionPool) Get() (net.Conn, error) {
	cp.mu.Lock()
	if cp.closed {
		cp.mu.Unlock()
		return nil, errors.New("pool is closed")
	}
	cp.mu.Unlock()

	// M4: Circuit breaker check
	if cp.CB != nil {
		if err := cp.CB.Allow(); err != nil {
			return nil, err
		}
	}

	select {
	case pc := <-cp.pool:
		// B2: Don't read from the connection to probe liveness — that corrupts the stream.
		// P7: Enforce MaxIdleTime; if stale, close and create a fresh connection.
		if cp.config.MaxIdleTime > 0 && time.Since(pc.pooled) >= cp.config.MaxIdleTime {
			pc.conn.Close()
			newConn, err := cp.factory()
			if err != nil {
				if cp.CB != nil {
					cp.CB.Failure()
				}
				return nil, err
			}
			if cp.CB != nil {
				cp.CB.Success()
			}
			atomic.AddInt64(&cp.activeConn, 1)
			return newConn, nil
		}
		pc.conn.SetDeadline(time.Time{})
		atomic.AddInt64(&cp.activeConn, 1)
		return pc.conn, nil
	default:
		// Create new connection if under max
		if atomic.LoadInt64(&cp.activeConn) < int64(cp.config.MaxConnections) {
			conn, err := cp.factory()
			if err != nil {
				if cp.CB != nil {
					cp.CB.Failure()
				}
				return nil, err
			}
			if cp.CB != nil {
				cp.CB.Success()
			}
			atomic.AddInt64(&cp.activeConn, 1)
			return conn, nil
		}

		// Wait for available connection
		pc := <-cp.pool
		atomic.AddInt64(&cp.activeConn, 1)
		return pc.conn, nil
	}
}

// Put returns a connection to the pool
func (cp *ConnectionPool) Put(conn net.Conn) error {
	if conn == nil {
		return nil
	}

	cp.mu.Lock()
	if cp.closed {
		cp.mu.Unlock()
		return conn.Close()
	}
	cp.mu.Unlock()

	select {
	case cp.pool <- &pooledConn{conn: conn, pooled: time.Now()}:
		// B1: decrement activeConn when connection is returned to the pool
		atomic.AddInt64(&cp.activeConn, -1)
		return nil
	default:
		// Pool is full, close connection
		atomic.AddInt64(&cp.activeConn, -1)
		return conn.Close()
	}
}

// Close closes all connections in the pool
func (cp *ConnectionPool) Close() error {
	cp.mu.Lock()
	if cp.closed {
		cp.mu.Unlock()
		return nil
	}
	cp.closed = true
	cp.mu.Unlock()

	// Signal eviction goroutine to stop
	select {
	case <-cp.done:
	default:
		close(cp.done)
	}

	close(cp.pool)
	for pc := range cp.pool {
		pc.conn.Close()
	}

	return nil
}

// ActiveConnections returns the number of connections checked out from the pool.
func (cp *ConnectionPool) ActiveConnections() int64 {
	return atomic.LoadInt64(&cp.activeConn)
}

// =============================================================================
// Message Framing
// =============================================================================

// FrameWriter writes length-prefixed messages
type FrameWriter struct {
	writer io.Writer
	mu     sync.Mutex
}

// NewFrameWriter creates a frame writer
func NewFrameWriter(w io.Writer) *FrameWriter {
	return &FrameWriter{writer: w}
}

// WriteFrame writes a length-prefixed frame
func (fw *FrameWriter) WriteFrame(data []byte) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	return framing.WriteFrame(fw.writer, data)
}

// FrameReader reads length-prefixed messages
type FrameReader struct {
	reader io.Reader
	mu     sync.Mutex
}

// NewFrameReader creates a frame reader
func NewFrameReader(r io.Reader) *FrameReader {
	return &FrameReader{reader: r}
}

// ReadFrame reads a length-prefixed frame
func (fr *FrameReader) ReadFrame() ([]byte, error) {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	return framing.ReadFrame(fr.reader)
}

// =============================================================================
// Keep-Alive Connection
// =============================================================================

// KeepAliveConn wraps a connection with keep-alive
type KeepAliveConn struct {
	conn          net.Conn
	keepAlive     time.Duration
	lastActivity  time.Time
	mu            sync.Mutex
	done          chan struct{}
	closeOnce     sync.Once
}

// NewKeepAliveConn creates a keep-alive connection
func NewKeepAliveConn(conn net.Conn, keepAlive time.Duration) *KeepAliveConn {
	kac := &KeepAliveConn{
		conn:         conn,
		keepAlive:    keepAlive,
		lastActivity: time.Now(),
		done:         make(chan struct{}),
	}

	if tcp, ok := conn.(*net.TCPConn); ok {
		tcp.SetKeepAlive(true)
		tcp.SetKeepAlivePeriod(keepAlive)
	}

	go kac.heartbeat()
	return kac
}

func (kac *KeepAliveConn) heartbeat() {
	ticker := time.NewTicker(kac.keepAlive / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			kac.mu.Lock()
			if time.Since(kac.lastActivity) > kac.keepAlive {
				kac.mu.Unlock()
				kac.Close()
				return
			}
			kac.mu.Unlock()
		case <-kac.done:
			return
		}
	}
}

// Read reads from connection and updates activity
func (kac *KeepAliveConn) Read(b []byte) (int, error) {
	n, err := kac.conn.Read(b)
	if n > 0 {
		kac.mu.Lock()
		kac.lastActivity = time.Now()
		kac.mu.Unlock()
	}
	return n, err
}

// Write writes to connection and updates activity
func (kac *KeepAliveConn) Write(b []byte) (int, error) {
	n, err := kac.conn.Write(b)
	if n > 0 {
		kac.mu.Lock()
		kac.lastActivity = time.Now()
		kac.mu.Unlock()
	}
	return n, err
}

// Close closes the connection
func (kac *KeepAliveConn) Close() error {
	var err error
	kac.closeOnce.Do(func() {
		close(kac.done)
		err = kac.conn.Close()
	})
	return err
}

// P10: Implement remaining net.Conn interface methods so KeepAliveConn is a drop-in replacement.
func (kac *KeepAliveConn) LocalAddr() net.Addr                { return kac.conn.LocalAddr() }
func (kac *KeepAliveConn) RemoteAddr() net.Addr               { return kac.conn.RemoteAddr() }
func (kac *KeepAliveConn) SetDeadline(t time.Time) error      { return kac.conn.SetDeadline(t) }
func (kac *KeepAliveConn) SetReadDeadline(t time.Time) error  { return kac.conn.SetReadDeadline(t) }
func (kac *KeepAliveConn) SetWriteDeadline(t time.Time) error { return kac.conn.SetWriteDeadline(t) }

// =============================================================================
// Echo Server (Common Pattern)
// =============================================================================

// EchoServer creates an echo server handler
func EchoServer() Handler {
	return func(conn net.Conn) {
		io.Copy(conn, conn)
	}
}

// =============================================================================
// Request-Response Pattern
// =============================================================================

// RequestResponseClient handles request-response communication
type RequestResponseClient struct {
	conn   net.Conn
	reader *FrameReader
	writer *FrameWriter
	mu     sync.Mutex
}

// NewRequestResponseClient creates a request-response client
func NewRequestResponseClient(conn net.Conn) *RequestResponseClient {
	return &RequestResponseClient{
		conn:   conn,
		reader: NewFrameReader(conn),
		writer: NewFrameWriter(conn),
	}
}

// SendRequest sends a request and waits for response
func (rrc *RequestResponseClient) SendRequest(ctx context.Context, request []byte) ([]byte, error) {
	rrc.mu.Lock()
	defer rrc.mu.Unlock()

	// Send request
	if err := rrc.writer.WriteFrame(request); err != nil {
		return nil, fmt.Errorf("send failed: %w", err)
	}

	// C2: Fix goroutine leak - use buffered channel so goroutine can always send
	type readResult struct {
		data []byte
		err  error
	}
	resultCh := make(chan readResult, 1)

	go func() {
		data, err := rrc.reader.ReadFrame()
		resultCh <- readResult{data, err}
	}()

	select {
	case <-ctx.Done():
		// Set deadline to unblock the goroutine
		rrc.conn.SetReadDeadline(time.Now().Add(time.Millisecond))
		return nil, ctx.Err()
	case result := <-resultCh:
		if result.err != nil {
			return nil, result.err
		}
		return result.data, nil
	}
}

// Close closes the client
func (rrc *RequestResponseClient) Close() error {
	return rrc.conn.Close()
}

// =============================================================================
// Circuit Breaker (M4)
// =============================================================================

// CBState represents the circuit breaker state
type CBState int

const (
	CBClosed   CBState = iota
	CBOpen
	CBHalfOpen
)

// ErrCircuitOpen is returned when the circuit is open
var ErrCircuitOpen = errors.New("circuit breaker open")

// CircuitBreaker implements the circuit breaker pattern
type CircuitBreaker struct {
	FailureThreshold int
	RecoveryTimeout  time.Duration
	mu               sync.Mutex
	state            CBState
	failures         int
	openedAt         time.Time
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(failureThreshold int, recoveryTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		FailureThreshold: failureThreshold,
		RecoveryTimeout:  recoveryTimeout,
	}
}

// Allow returns nil if the circuit is closed/half-open, ErrCircuitOpen otherwise
func (cb *CircuitBreaker) Allow() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	switch cb.state {
	case CBClosed:
		return nil
	case CBOpen:
		if time.Since(cb.openedAt) >= cb.RecoveryTimeout {
			cb.state = CBHalfOpen
			return nil
		}
		return ErrCircuitOpen
	case CBHalfOpen:
		return nil
	}
	return nil
}

// Success records a successful operation
func (cb *CircuitBreaker) Success() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
	cb.state = CBClosed
}

// Failure records a failed operation
func (cb *CircuitBreaker) Failure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures++
	if cb.failures >= cb.FailureThreshold || cb.state == CBHalfOpen {
		cb.state = CBOpen
		cb.openedAt = time.Now()
	}
}

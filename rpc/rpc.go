/*
RPC Implementation
==================

Simplified RPC (Remote Procedure Call) framework demonstrating core concepts
similar to gRPC, with support for multiple streaming patterns.

Applications:
- Microservices communication
- Distributed systems
- Service-to-service calls
- API gateways
*/

package rpc

import (
	"context"
	"crypto/tls"
	"encoding/json"
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
// Message Types and Protocol
// =============================================================================

// MessageType defines the type of RPC message
type MessageType byte

const (
	MessageTypeRequest  MessageType = 0x01
	MessageTypeResponse MessageType = 0x02
	MessageTypeError    MessageType = 0x03
	MessageTypeStream   MessageType = 0x04
	MessageTypeEOF      MessageType = 0x05
)

// StreamType defines the streaming pattern
type StreamType byte

const (
	StreamTypeUnary              StreamType = 0x01 // Single request, single response
	StreamTypeServerStreaming    StreamType = 0x02 // Single request, stream of responses
	StreamTypeClientStreaming    StreamType = 0x03 // Stream of requests, single response
	StreamTypeBidirectionalStream StreamType = 0x04 // Stream of requests and responses
)

// M7: RPC structured error codes
const (
	ErrCodeOK               = 0
	ErrCodeCanceled         = 1
	ErrCodeUnknown          = 2
	ErrCodeDeadlineExceeded = 4
	ErrCodeNotFound         = 5
	ErrCodeInternal         = 13
	ErrCodeUnavailable      = 14
)

// Message represents an RPC message
type Message struct {
	Type      MessageType `json:"type"`
	RequestID uint64      `json:"request_id"`
	Method    string      `json:"method,omitempty"`
	Payload   []byte      `json:"payload,omitempty"`
	Error     string      `json:"error,omitempty"`
	ErrCode   int         `json:"err_code,omitempty"`
	Deadline  int64       `json:"deadline,omitempty"` // C3: unix nanoseconds
}

// =============================================================================
// RPC Server
// =============================================================================

// Handler is a function that handles RPC requests
type Handler func(ctx context.Context, request []byte) ([]byte, error)

// StreamHandler is a function that handles streaming RPC requests
type StreamHandler func(stream ServerStream) error

// UnaryInterceptor intercepts unary RPC calls. (P3)
type UnaryInterceptor func(ctx context.Context, method string, req []byte, handler Handler) ([]byte, error)

// StreamInterceptorFunc intercepts streaming RPC calls. (P3)
type StreamInterceptorFunc func(method string, stream ServerStream, handler StreamHandler) error

// Server represents an RPC server
type Server struct {
	Address            string
	StopTimeout        time.Duration // P8: configurable drain timeout
	handlers           map[string]Handler
	streamHandlers     map[string]StreamHandler
	UnaryInterceptors  []UnaryInterceptor     // P3
	StreamInterceptors []StreamInterceptorFunc // P3
	listener           net.Listener
	done               chan struct{}
	wg                 sync.WaitGroup
	mu                 sync.RWMutex
	active             bool
	requestCounter     uint64
	activeConns        int64
}

// contextFromDeadline reconstructs a context from a unix nanosecond deadline. (C3)
func contextFromDeadline(deadline int64) (context.Context, context.CancelFunc) {
	if deadline == 0 {
		return context.Background(), func() {}
	}
	d := time.Unix(0, deadline)
	if d.Before(time.Now()) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // already expired
		return ctx, cancel
	}
	return context.WithDeadline(context.Background(), d)
}

// NewServer creates a new RPC server
func NewServer(address string) *Server {
	s := &Server{
		Address:        address,
		handlers:       make(map[string]Handler),
		streamHandlers: make(map[string]StreamHandler),
		done:           make(chan struct{}),
	}
	// L6: Built-in reflection handler
	s.handlers["__reflection__"] = func(ctx context.Context, req []byte) ([]byte, error) {
		s.mu.RLock()
		methods := make([]string, 0, len(s.handlers)+len(s.streamHandlers))
		for m := range s.handlers {
			methods = append(methods, m)
		}
		for m := range s.streamHandlers {
			methods = append(methods, "stream:"+m)
		}
		s.mu.RUnlock()
		return json.Marshal(methods)
	}
	return s
}

// Register registers a unary RPC handler
func (s *Server) Register(method string, handler Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[method] = handler
}

// RegisterStream registers a streaming RPC handler
func (s *Server) RegisterStream(method string, handler StreamHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.streamHandlers[method] = handler
}

// Start starts the RPC server
func (s *Server) Start() error {
	s.mu.Lock()
	if s.active {
		s.mu.Unlock()
		return errors.New("server already running")
	}

	listener, err := net.Listen("tcp", s.Address)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("listen failed: %w", err)
	}

	s.listener = listener
	s.active = true
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

		atomic.AddInt64(&s.activeConns, 1)
		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()
	defer atomic.AddInt64(&s.activeConns, -1)

	for {
		msg, err := s.readMessage(conn)
		if err != nil {
			if err != io.EOF {
				s.sendError(conn, 0, fmt.Sprintf("read error: %v", err))
			}
			return
		}

		// Handle based on message type
		if msg.Type == MessageTypeRequest {
			s.handleRequest(conn, msg)
		} else if msg.Type == MessageTypeStream {
			s.handleStreamRequest(conn, msg)
		}
	}
}

func (s *Server) handleRequest(conn net.Conn, msg *Message) {
	// C1: Panic recovery
	defer func() {
		if r := recover(); r != nil {
			slog.Error("rpc: panic in handler", "method", msg.Method, "err", r)
			s.sendErrorWithCode(conn, msg.RequestID, "internal server error", ErrCodeInternal)
		}
	}()

	s.mu.RLock()
	handler, ok := s.handlers[msg.Method]
	s.mu.RUnlock()

	if !ok {
		s.sendErrorWithCode(conn, msg.RequestID, fmt.Sprintf("method not found: %s", msg.Method), ErrCodeNotFound)
		return
	}

	// B12: Increment request counter now that we have a valid handler.
	atomic.AddUint64(&s.requestCounter, 1)

	// C3: Reconstruct context from deadline
	ctx, cancel := contextFromDeadline(msg.Deadline)
	defer cancel()

	// P3: Route through unary interceptor chain if any are registered.
	var response []byte
	var err error
	if len(s.UnaryInterceptors) > 0 {
		response, err = s.chainUnaryInterceptors(ctx, msg.Method, msg.Payload, handler)
	} else {
		response, err = handler(ctx, msg.Payload)
	}

	if err != nil {
		s.sendErrorWithCode(conn, msg.RequestID, err.Error(), ErrCodeInternal)
	} else {
		s.sendResponse(conn, msg.RequestID, response)
	}
}

// chainUnaryInterceptors builds and executes the unary interceptor chain. (P3)
func (s *Server) chainUnaryInterceptors(ctx context.Context, method string, req []byte, handler Handler) ([]byte, error) {
	if len(s.UnaryInterceptors) == 0 {
		return handler(ctx, req)
	}
	var chain func(i int) Handler
	chain = func(i int) Handler {
		if i >= len(s.UnaryInterceptors) {
			return handler
		}
		return func(ctx context.Context, req []byte) ([]byte, error) {
			return s.UnaryInterceptors[i](ctx, method, req, chain(i+1))
		}
	}
	return chain(0)(ctx, req)
}

// chainStreamInterceptors builds and executes the stream interceptor chain. (P3)
func (s *Server) chainStreamInterceptors(method string, stream ServerStream, handler StreamHandler) error {
	if len(s.StreamInterceptors) == 0 {
		return handler(stream)
	}
	var chain func(i int) StreamHandler
	chain = func(i int) StreamHandler {
		if i >= len(s.StreamInterceptors) {
			return handler
		}
		return func(st ServerStream) error {
			return s.StreamInterceptors[i](method, st, chain(i+1))
		}
	}
	return chain(0)(stream)
}

func (s *Server) handleStreamRequest(conn net.Conn, msg *Message) {
	// C1: Panic recovery
	defer func() {
		if r := recover(); r != nil {
			slog.Error("rpc: panic in stream handler", "method", msg.Method, "err", r)
			s.sendErrorWithCode(conn, msg.RequestID, "internal server error", ErrCodeInternal)
		}
	}()

	s.mu.RLock()
	handler, ok := s.streamHandlers[msg.Method]
	s.mu.RUnlock()

	if !ok {
		s.sendErrorWithCode(conn, msg.RequestID, fmt.Sprintf("stream method not found: %s", msg.Method), ErrCodeNotFound)
		return
	}

	// B4: Reconstruct context from the client deadline and store in the stream.
	streamCtx, streamCancel := contextFromDeadline(msg.Deadline)
	defer streamCancel()

	stream := &serverStream{
		conn:      conn,
		requestID: msg.RequestID,
		server:    s,
		ctx:       streamCtx,
	}

	// P3: Route through stream interceptor chain if any are registered.
	var err error
	if len(s.StreamInterceptors) > 0 {
		err = s.chainStreamInterceptors(msg.Method, stream, handler)
	} else {
		err = handler(stream)
	}

	if err != nil {
		s.sendErrorWithCode(conn, msg.RequestID, err.Error(), ErrCodeInternal)
		return
	}
	// Send EOF to signal end of stream to the client.
	eofMsg := &Message{
		Type:      MessageTypeEOF,
		RequestID: msg.RequestID,
	}
	s.writeMessage(conn, eofMsg)
}

func (s *Server) readMessage(conn net.Conn) (*Message, error) {
	msgBuf, err := framing.ReadFrame(conn)
	if err != nil {
		return nil, err
	}

	var msg Message
	if err := json.Unmarshal(msgBuf, &msg); err != nil {
		return nil, err
	}

	return &msg, nil
}

func (s *Server) writeMessage(conn net.Conn, msg *Message) error {
	msgBuf, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return framing.WriteFrame(conn, msgBuf)
}

func (s *Server) sendResponse(conn net.Conn, requestID uint64, payload []byte) error {
	msg := &Message{
		Type:      MessageTypeResponse,
		RequestID: requestID,
		Payload:   payload,
	}
	return s.writeMessage(conn, msg)
}

func (s *Server) sendError(conn net.Conn, requestID uint64, errMsg string) error {
	return s.sendErrorWithCode(conn, requestID, errMsg, ErrCodeInternal)
}

func (s *Server) sendErrorWithCode(conn net.Conn, requestID uint64, errMsg string, code int) error {
	msg := &Message{
		Type:      MessageTypeError,
		RequestID: requestID,
		Error:     errMsg,
		ErrCode:   code,
	}
	return s.writeMessage(conn, msg)
}

// ListenTLS starts the RPC server with TLS. (H2)
func (s *Server) ListenTLS(cfg *tls.Config) error {
	s.mu.Lock()
	if s.active {
		s.mu.Unlock()
		return errors.New("server already running")
	}

	ln, err := tls.Listen("tcp", s.Address, cfg)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("TLS listen failed: %w", err)
	}

	s.listener = ln
	s.active = true
	s.mu.Unlock()

	s.wg.Add(1)
	go s.acceptLoop()

	return nil
}

// Stop stops the RPC server. (P8: drain with configurable timeout)
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

	// P8: Drain active handlers with a timeout instead of blocking forever.
	timeout := s.StopTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		slog.Warn("rpc: drain timeout exceeded")
	}
	return nil
}

// GetStats returns server statistics
func (s *Server) GetStats() (activeConns int64, totalRequests uint64) {
	return atomic.LoadInt64(&s.activeConns), atomic.LoadUint64(&s.requestCounter)
}

// =============================================================================
// RPC Client
// =============================================================================

// Client represents an RPC client
type Client struct {
	Address             string
	MaxRetries          int
	RetryDelay          time.Duration
	DefaultCallTimeout  time.Duration // M6: per-call timeout default
	conn                net.Conn
	mu                  sync.Mutex
	requestID           uint64
	pendingCalls        map[uint64]chan *Message
	pendingMu           sync.RWMutex
	streamChans         map[uint64]chan *Message // M8: stream demux
	streamMu            sync.RWMutex
	done                chan struct{}
	connected           bool
}

// NewClient creates a new RPC client
func NewClient(address string) *Client {
	return &Client{
		Address:            address,
		MaxRetries:         5,
		RetryDelay:         time.Second,
		DefaultCallTimeout: 30 * time.Second, // M6
		pendingCalls:       make(map[uint64]chan *Message),
		streamChans:        make(map[uint64]chan *Message), // M8
		done:               make(chan struct{}),
	}
}

// Connect connects to the RPC server
func (c *Client) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return errors.New("already connected")
	}

	conn, err := net.Dial("tcp", c.Address)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}

	c.conn = conn
	c.connected = true

	go c.readLoop()

	return nil
}

// DialTLS connects to the RPC server using TLS. (H2)
func (c *Client) DialTLS(addr string, cfg *tls.Config) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return errors.New("already connected")
	}

	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		return fmt.Errorf("TLS dial failed: %w", err)
	}

	c.conn = conn
	c.connected = true

	go c.readLoop()

	return nil
}

// failPendingCalls delivers an error to all in-flight unary and stream calls. (P9)
func (c *Client) failPendingCalls(err error) {
	c.pendingMu.Lock()
	for id, ch := range c.pendingCalls {
		ch <- &Message{Type: MessageTypeError, RequestID: id, Error: err.Error(), ErrCode: ErrCodeUnavailable}
		delete(c.pendingCalls, id)
	}
	c.pendingMu.Unlock()

	c.streamMu.Lock()
	for id, ch := range c.streamChans {
		select {
		case ch <- &Message{Type: MessageTypeError, RequestID: id, Error: err.Error(), ErrCode: ErrCodeUnavailable}:
		default:
		}
		delete(c.streamChans, id)
	}
	c.streamMu.Unlock()
}

// reconnect attempts to re-dial the server with exponential backoff
func (c *Client) reconnect() {
	// P9: Fail all in-flight calls so callers are not left hanging forever.
	c.failPendingCalls(errors.New("connection lost, reconnecting"))

	delay := c.RetryDelay
	maxRetries := c.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 5
	}
	if delay <= 0 {
		delay = time.Second
	}

	for attempt := 0; attempt < maxRetries; attempt++ {
		select {
		case <-c.done:
			return
		case <-time.After(delay):
		}
		delay *= 2

		conn, err := net.Dial("tcp", c.Address)
		if err != nil {
			continue
		}

		c.mu.Lock()
		c.conn = conn
		c.connected = true
		c.mu.Unlock()

		go c.readLoop()
		return
	}
}

func (c *Client) readLoop() {
	for {
		msg, err := c.readMessage()
		if err != nil {
			select {
			case <-c.done:
				return
			default:
				// Connection lost – mark disconnected and attempt reconnect
				c.mu.Lock()
				c.connected = false
				c.mu.Unlock()
				go c.reconnect()
				return
			}
		}

		// M8: Route stream messages to streamChans, unary to pendingCalls
		if msg.Type == MessageTypeStream || msg.Type == MessageTypeEOF {
			c.streamMu.RLock()
			ch, ok := c.streamChans[msg.RequestID]
			c.streamMu.RUnlock()
			if ok {
				ch <- msg
				continue
			}
		}

		// Deliver to pending call
		c.pendingMu.RLock()
		ch, ok := c.pendingCalls[msg.RequestID]
		c.pendingMu.RUnlock()

		if ok {
			ch <- msg
		}
	}
}

// Call makes a unary RPC call
func (c *Client) Call(ctx context.Context, method string, request []byte) ([]byte, error) {
	// M6: Apply default call timeout if ctx has no deadline
	if _, hasDeadline := ctx.Deadline(); !hasDeadline && c.DefaultCallTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.DefaultCallTimeout)
		defer cancel()
	}

	c.mu.Lock()
	if !c.connected {
		c.mu.Unlock()
		return nil, errors.New("not connected")
	}

	requestID := atomic.AddUint64(&c.requestID, 1)
	c.mu.Unlock()

	// Create response channel
	respCh := make(chan *Message, 1)
	c.pendingMu.Lock()
	c.pendingCalls[requestID] = respCh
	c.pendingMu.Unlock()

	defer func() {
		c.pendingMu.Lock()
		delete(c.pendingCalls, requestID)
		c.pendingMu.Unlock()
	}()

	// Send request
	msg := &Message{
		Type:      MessageTypeRequest,
		RequestID: requestID,
		Method:    method,
		Payload:   request,
	}

	// C3: Thread deadline through to server
	if deadline, ok := ctx.Deadline(); ok {
		msg.Deadline = deadline.UnixNano()
	}

	if err := c.writeMessage(msg); err != nil {
		return nil, err
	}

	// Wait for response
	select {
	case resp := <-respCh:
		if resp.Type == MessageTypeError {
			return nil, errors.New(resp.Error)
		}
		return resp.Payload, nil
	case <-ctx.Done():
		// C4: Drain buffered response if any
		select {
		case <-respCh:
		default:
		}
		return nil, ctx.Err()
	}
}

// ListMethods queries the server for all registered methods via reflection. (L6)
func (c *Client) ListMethods(ctx context.Context) ([]string, error) {
	data, err := c.Call(ctx, "__reflection__", nil)
	if err != nil {
		return nil, err
	}
	var methods []string
	return methods, json.Unmarshal(data, &methods)
}

// Stream creates a streaming RPC call
func (c *Client) Stream(ctx context.Context, method string) (ClientStream, error) {
	c.mu.Lock()
	if !c.connected {
		c.mu.Unlock()
		return nil, errors.New("not connected")
	}

	requestID := atomic.AddUint64(&c.requestID, 1)
	c.mu.Unlock()

	stream := &clientStream{
		client:    c,
		requestID: requestID,
		method:    method,
		ctx:       ctx,
		recvCh:    make(chan *Message, 10),
	}

	// M8: Register in streamChans for dedicated stream demux
	c.streamMu.Lock()
	c.streamChans[requestID] = stream.recvCh
	c.streamMu.Unlock()

	return stream, nil
}

func (c *Client) readMessage() (*Message, error) {
	msgBuf, err := framing.ReadFrame(c.conn)
	if err != nil {
		return nil, err
	}

	var msg Message
	if err := json.Unmarshal(msgBuf, &msg); err != nil {
		return nil, err
	}

	return &msg, nil
}

func (c *Client) writeMessage(msg *Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	msgBuf, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return framing.WriteFrame(c.conn, msgBuf)
}

// Close closes the client connection
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil
	}

	close(c.done)
	c.connected = false
	return c.conn.Close()
}

// =============================================================================
// Streaming Interfaces
// =============================================================================

// ServerStream represents a server-side stream
type ServerStream interface {
	Send(data []byte) error
	Recv() ([]byte, error)
	Context() context.Context
}

// ClientStream represents a client-side stream
type ClientStream interface {
	Send(data []byte) error
	Recv() ([]byte, error)
	CloseSend() error
	Context() context.Context
}

// serverStream implements ServerStream
type serverStream struct {
	conn      net.Conn
	requestID uint64
	server    *Server
	mu        sync.Mutex
	ctx       context.Context // B4: derived from the client's deadline
}

func (s *serverStream) Send(data []byte) error {
	msg := &Message{
		Type:      MessageTypeStream,
		RequestID: s.requestID,
		Payload:   data,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.server.writeMessage(s.conn, msg)
}

func (s *serverStream) Recv() ([]byte, error) {
	msg, err := s.server.readMessage(s.conn)
	if err != nil {
		return nil, err
	}

	if msg.Type == MessageTypeEOF {
		return nil, io.EOF
	}

	return msg.Payload, nil
}

// Context returns the context derived from the client's deadline. (B4)
func (s *serverStream) Context() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

// clientStream implements ClientStream
type clientStream struct {
	client    *Client
	requestID uint64
	method    string
	ctx       context.Context
	recvCh    chan *Message
	mu        sync.Mutex
	closed    bool
}

func (s *clientStream) Send(data []byte) error {
	msg := &Message{
		Type:      MessageTypeStream,
		RequestID: s.requestID,
		Method:    s.method,
		Payload:   data,
	}

	return s.client.writeMessage(msg)
}

func (s *clientStream) Recv() ([]byte, error) {
	select {
	case msg := <-s.recvCh:
		if msg.Type == MessageTypeEOF {
			return nil, io.EOF
		}
		if msg.Type == MessageTypeError {
			return nil, errors.New(msg.Error)
		}
		return msg.Payload, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}

func (s *clientStream) CloseSend() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	msg := &Message{
		Type:      MessageTypeEOF,
		RequestID: s.requestID,
	}

	s.closed = true
	// M8: Cleanup streamChans entry
	s.client.streamMu.Lock()
	delete(s.client.streamChans, s.requestID)
	s.client.streamMu.Unlock()

	return s.client.writeMessage(msg)
}

func (s *clientStream) Context() context.Context {
	return s.ctx
}

// =============================================================================
// Load Balancer for RPC
// =============================================================================

// LoadBalancedClient wraps multiple RPC clients with load balancing
type LoadBalancedClient struct {
	clients   []*Client
	strategy  string // "round-robin", "random", "least-conn"
	current   uint64
	connCounts []int64
	mu        sync.RWMutex
}

// NewLoadBalancedClient creates a load-balanced RPC client
func NewLoadBalancedClient(addresses []string, strategy string) (*LoadBalancedClient, error) {
	if len(addresses) == 0 {
		return nil, errors.New("no addresses provided")
	}

	clients := make([]*Client, len(addresses))
	connCounts := make([]int64, len(addresses))

	for i, addr := range addresses {
		client := NewClient(addr)
		if err := client.Connect(); err != nil {
			// Close already connected clients
			for j := 0; j < i; j++ {
				clients[j].Close()
			}
			return nil, fmt.Errorf("connect to %s failed: %w", addr, err)
		}
		clients[i] = client
	}

	return &LoadBalancedClient{
		clients:    clients,
		strategy:   strategy,
		connCounts: connCounts,
	}, nil
}

// Call makes a load-balanced RPC call
func (lb *LoadBalancedClient) Call(ctx context.Context, method string, request []byte) ([]byte, error) {
	client, idx := lb.selectClientWithIndex()
	// C6: Decrement activeConns after call for least-conn strategy
	defer func() {
		if lb.strategy == "least-conn" && idx >= 0 {
			atomic.AddInt64(&lb.connCounts[idx], -1)
		}
	}()
	return client.Call(ctx, method, request)
}

func (lb *LoadBalancedClient) selectClientWithIndex() (*Client, int) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	switch lb.strategy {
	case "round-robin":
		idx := atomic.AddUint64(&lb.current, 1) % uint64(len(lb.clients))
		return lb.clients[idx], int(idx)

	case "random":
		idx := time.Now().UnixNano() % int64(len(lb.clients))
		return lb.clients[idx], -1

	case "least-conn":
		minIdx := 0
		minConns := atomic.LoadInt64(&lb.connCounts[0])
		for i := 1; i < len(lb.clients); i++ {
			conns := atomic.LoadInt64(&lb.connCounts[i])
			if conns < minConns {
				minConns = conns
				minIdx = i
			}
		}
		atomic.AddInt64(&lb.connCounts[minIdx], 1)
		return lb.clients[minIdx], minIdx

	default:
		return lb.clients[0], -1
	}
}

// Close closes all client connections
func (lb *LoadBalancedClient) Close() error {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	for _, client := range lb.clients {
		client.Close()
	}
	return nil
}

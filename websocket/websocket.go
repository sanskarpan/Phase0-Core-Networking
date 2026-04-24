/*
WebSocket Implementation
=======================

WebSocket support for real-time bidirectional communication.

Applications:
- Real-time chat applications
- Live data streaming
- Push notifications
- Collaborative editing
*/

package websocket

import (
	"bufio"
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// =============================================================================
// WebSocket Opcodes
// =============================================================================

const (
	OpcodeContinuation = 0x0
	OpcodeText         = 0x1
	OpcodeBinary       = 0x2
	OpcodeClose        = 0x8
	OpcodePing         = 0x9
	OpcodePong         = 0xA
)

// H9: WebSocket close codes per RFC 6455
const (
	CloseNormal        uint16 = 1000
	CloseGoingAway     uint16 = 1001
	CloseProtocolError uint16 = 1002
	CloseInternalError uint16 = 1011
)

// =============================================================================
// WebSocket Frame
// =============================================================================

// Frame represents a WebSocket frame
type Frame struct {
	Fin     bool
	RSV1    bool // P6: RFC 7692 §7.2.1 – set for compressed frames
	Opcode  byte
	Masked  bool
	Payload []byte
}

// =============================================================================
// WebSocket Connection
// =============================================================================

// defaultMaxMessageSize is the default maximum WebSocket message size (32 MB). (B5)
const defaultMaxMessageSize int64 = 32 * 1024 * 1024

// Conn represents a WebSocket connection
type Conn struct {
	conn           net.Conn
	isServer       bool
	mu             sync.Mutex
	writeMu        sync.Mutex
	closeOnce      sync.Once
	closed         bool
	pingInterval   time.Duration
	pongTimeout    time.Duration
	lastPong       time.Time
	done           chan struct{}
	MaxMessageSize int64 // B5: 0 = unlimited; default set in NewConn
	// H9: Close codes
	CloseCode   uint16
	CloseReason string
	// H10: Subprotocol
	protocol string
	// M12: Compression
	compressed bool
}

// NewConn creates a WebSocket connection
func NewConn(conn net.Conn, isServer bool) *Conn {
	wsc := &Conn{
		conn:           conn,
		isServer:       isServer,
		pingInterval:   30 * time.Second,
		pongTimeout:    10 * time.Second,
		lastPong:       time.Now(),
		done:           make(chan struct{}),
		MaxMessageSize: defaultMaxMessageSize, // B5: 32 MB default
	}

	if isServer {
		go wsc.pingLoop()
	}

	return wsc
}

// ReadFrame reads a WebSocket frame
func (c *Conn) ReadFrame() (*Frame, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errors.New("connection closed")
	}
	c.mu.Unlock()

	// Read first two bytes
	header := make([]byte, 2)
	if _, err := io.ReadFull(c.conn, header); err != nil {
		return nil, err
	}

	frame := &Frame{
		Fin:    header[0]&0x80 != 0,
		Opcode: header[0] & 0x0F,
		Masked: header[1]&0x80 != 0,
	}

	// C7: Control frames (opcode >= 0x8) MUST have FIN=1 per RFC 6455 §5.5
	isControl := frame.Opcode >= 0x8
	if isControl && !frame.Fin {
		return nil, errors.New("websocket: fragmented control frame")
	}

	// Read payload length
	payloadLen := int64(header[1] & 0x7F)
	if payloadLen == 126 {
		lenBytes := make([]byte, 2)
		if _, err := io.ReadFull(c.conn, lenBytes); err != nil {
			return nil, err
		}
		payloadLen = int64(binary.BigEndian.Uint16(lenBytes))
	} else if payloadLen == 127 {
		lenBytes := make([]byte, 8)
		if _, err := io.ReadFull(c.conn, lenBytes); err != nil {
			return nil, err
		}
		payloadLen = int64(binary.BigEndian.Uint64(lenBytes))
	}

	// B5: Enforce maximum message size to prevent OOM from malicious frames.
	if c.MaxMessageSize > 0 && payloadLen > c.MaxMessageSize {
		return nil, fmt.Errorf("websocket: message size %d exceeds limit %d", payloadLen, c.MaxMessageSize)
	}

	// Read masking key if present
	var maskKey []byte
	if frame.Masked {
		maskKey = make([]byte, 4)
		if _, err := io.ReadFull(c.conn, maskKey); err != nil {
			return nil, err
		}
	}

	// Read payload
	frame.Payload = make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(c.conn, frame.Payload); err != nil {
			return nil, err
		}

		// Unmask payload if needed
		if frame.Masked {
			for i := range frame.Payload {
				frame.Payload[i] ^= maskKey[i%4]
			}
		}
	}

	return frame, nil
}

// WriteFrame writes a WebSocket frame
func (c *Conn) WriteFrame(frame *Frame) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errors.New("connection closed")
	}
	c.mu.Unlock()

	// Build header
	header := make([]byte, 0, 10)

	// First byte: FIN, RSV1, and opcode
	b := byte(0)
	if frame.Fin {
		b |= 0x80
	}
	if frame.RSV1 {
		b |= 0x40 // P6: RSV1 bit per RFC 7692 §7.2.1 indicates permessage-deflate
	}
	b |= frame.Opcode & 0x0F
	header = append(header, b)

	// Second byte: mask and payload length
	payloadLen := len(frame.Payload)
	b = byte(0)
	if !c.isServer {
		b |= 0x80 // Client must mask
		frame.Masked = true
	}

	if payloadLen < 126 {
		b |= byte(payloadLen)
		header = append(header, b)
	} else if payloadLen < 65536 {
		b |= 126
		header = append(header, b)
		lenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBytes, uint16(payloadLen))
		header = append(header, lenBytes...)
	} else {
		b |= 127
		header = append(header, b)
		lenBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(lenBytes, uint64(payloadLen))
		header = append(header, lenBytes...)
	}

	// Add masking key if needed
	var maskKey []byte
	if frame.Masked {
		maskKey = make([]byte, 4)
		if _, err := io.ReadFull(rand.Reader, maskKey[:]); err != nil {
			return err
		}
		header = append(header, maskKey...)
	}

	// Write header
	if _, err := c.conn.Write(header); err != nil {
		return err
	}

	// Write payload
	if payloadLen > 0 {
		payload := frame.Payload
		if frame.Masked {
			payload = make([]byte, payloadLen)
			for i := range payload {
				payload[i] = frame.Payload[i] ^ maskKey[i%4]
			}
		}
		if _, err := c.conn.Write(payload); err != nil {
			return err
		}
	}

	return nil
}

// ReadMessage reads a complete WebSocket message
func (c *Conn) ReadMessage() (messageType byte, data []byte, err error) {
	for {
		frame, err := c.ReadFrame()
		if err != nil {
			return 0, nil, err
		}

		switch frame.Opcode {
		case OpcodeText, OpcodeBinary:
			messageType = frame.Opcode
			data = append(data, frame.Payload...)
			// B5: Check total accumulated message size.
			if c.MaxMessageSize > 0 && int64(len(data)) > c.MaxMessageSize {
				return 0, nil, fmt.Errorf("websocket: message size %d exceeds limit %d", len(data), c.MaxMessageSize)
			}
			if frame.Fin {
				return messageType, data, nil
			}

		case OpcodeContinuation:
			data = append(data, frame.Payload...)
			// B5: Check total accumulated message size.
			if c.MaxMessageSize > 0 && int64(len(data)) > c.MaxMessageSize {
				return 0, nil, fmt.Errorf("websocket: message size %d exceeds limit %d", len(data), c.MaxMessageSize)
			}
			if frame.Fin {
				return messageType, data, nil
			}

		case OpcodeClose:
			// H9: Parse close code from payload
			if len(frame.Payload) >= 2 {
				c.mu.Lock()
				c.CloseCode = binary.BigEndian.Uint16(frame.Payload[:2])
				if len(frame.Payload) > 2 {
					c.CloseReason = string(frame.Payload[2:])
				}
				c.mu.Unlock()
			}
			c.CloseWithCode(CloseNormal, "")
			return 0, nil, errors.New("connection closed by peer")

		case OpcodePing:
			// Send pong
			c.WriteFrame(&Frame{
				Fin:     true,
				Opcode:  OpcodePong,
				Payload: frame.Payload,
			})

		case OpcodePong:
			c.mu.Lock()
			c.lastPong = time.Now()
			c.mu.Unlock()
		}
	}
}

// WriteMessage writes a complete WebSocket message
func (c *Conn) WriteMessage(messageType byte, data []byte) error {
	return c.WriteFrame(&Frame{
		Fin:     true,
		Opcode:  messageType,
		Payload: data,
	})
}

// WriteText writes a text message
func (c *Conn) WriteText(text string) error {
	return c.WriteMessage(OpcodeText, []byte(text))
}

// WriteBinary writes a binary message
func (c *Conn) WriteBinary(data []byte) error {
	return c.WriteMessage(OpcodeBinary, data)
}

// Ping sends a ping frame
func (c *Conn) Ping() error {
	return c.WriteFrame(&Frame{
		Fin:    true,
		Opcode: OpcodePing,
	})
}

func (c *Conn) pingLoop() {
	// C1: Panic recovery
	defer func() {
		if r := recover(); r != nil {
			slog.Error("websocket: panic in pingLoop", "err", r)
		}
	}()

	ticker := time.NewTicker(c.pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := c.Ping(); err != nil {
				c.Close()
				return
			}

			c.mu.Lock()
			if time.Since(c.lastPong) > c.pingInterval+c.pongTimeout {
				c.mu.Unlock()
				c.Close()
				return
			}
			c.mu.Unlock()

		case <-c.done:
			return
		}
	}
}

// Close closes the WebSocket connection
func (c *Conn) Close() error {
	return c.CloseWithCode(CloseNormal, "")
}

// CloseWithCode sends a Close frame with the given status code and reason. (H9)
func (c *Conn) CloseWithCode(code uint16, reason string) error {
	var err error
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.CloseCode = code
		c.CloseReason = reason
		c.mu.Unlock()

		close(c.done)

		// Build close payload: 2-byte code + reason
		payload := make([]byte, 2+len(reason))
		binary.BigEndian.PutUint16(payload[:2], code)
		copy(payload[2:], reason)

		c.WriteFrame(&Frame{Fin: true, Opcode: OpcodeClose, Payload: payload})
		err = c.conn.Close()
	})
	return err
}

// Protocol returns the negotiated subprotocol. (H10)
func (c *Conn) Protocol() string { return c.protocol }

// WriteCompressedMessage writes a compressed binary message. (M12, P6)
func (c *Conn) WriteCompressedMessage(data []byte) error {
	if !c.compressed {
		return c.WriteMessage(OpcodeBinary, data)
	}
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	w.Write(data)
	w.Close()
	// P6: Set RSV1 bit to indicate permessage-deflate compression per RFC 7692 §7.2.1
	return c.WriteFrame(&Frame{Fin: true, RSV1: true, Opcode: OpcodeBinary, Payload: buf.Bytes()})
}

// =============================================================================
// WebSocket Upgrade
// =============================================================================

// Upgrader handles WebSocket upgrade
type Upgrader struct {
	CheckOrigin       func(r *http.Request) bool
	Protocols         []string   // H10: supported subprotocols
	EnableCompression bool       // M12: permessage-deflate
	TLSConfig         *tls.Config // H3
}

// NewUpgrader creates a WebSocket upgrader
func NewUpgrader() *Upgrader {
	return &Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
}

// Upgrade upgrades an HTTP connection to WebSocket
func (u *Upgrader) Upgrade(w http.ResponseWriter, r *http.Request) (*Conn, error) {
	// Check upgrade headers
	if strings.ToLower(r.Header.Get("Upgrade")) != "websocket" {
		return nil, errors.New("missing or invalid Upgrade header")
	}

	if !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		return nil, errors.New("missing or invalid Connection header")
	}

	// Check origin if needed
	if u.CheckOrigin != nil && !u.CheckOrigin(r) {
		return nil, errors.New("origin not allowed")
	}

	// Get WebSocket key
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, errors.New("missing Sec-WebSocket-Key header")
	}

	// Calculate accept key
	const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	h.Write([]byte(key + magic))
	acceptKey := base64.StdEncoding.EncodeToString(h.Sum(nil))

	// Hijack connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("response writer does not support hijacking")
	}

	conn, bufrw, err := hijacker.Hijack()
	if err != nil {
		return nil, fmt.Errorf("hijack failed: %w", err)
	}

	// H10: Subprotocol negotiation
	negotiated := ""
	if len(u.Protocols) > 0 {
		reqProtos := strings.Split(r.Header.Get("Sec-WebSocket-Protocol"), ",")
		for _, rp := range reqProtos {
			rp = strings.TrimSpace(rp)
			for _, up := range u.Protocols {
				if rp == up {
					negotiated = rp
					break
				}
			}
			if negotiated != "" {
				break
			}
		}
	}

	// Write upgrade response
	response := fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Accept: %s\r\n", acceptKey)

	if negotiated != "" {
		response += fmt.Sprintf("Sec-WebSocket-Protocol: %s\r\n", negotiated)
	}
	response += "\r\n"

	if _, err := bufrw.Write([]byte(response)); err != nil {
		conn.Close()
		return nil, err
	}

	if err := bufrw.Flush(); err != nil {
		conn.Close()
		return nil, err
	}

	wsConn := NewConn(conn, true)
	wsConn.protocol = negotiated
	wsConn.compressed = u.EnableCompression
	return wsConn, nil
}

// =============================================================================
// WebSocket Server
// =============================================================================

// MessageHandler handles WebSocket messages
type MessageHandler func(conn *Conn, messageType byte, data []byte)

// Server represents a WebSocket server
type Server struct {
	Upgrader *Upgrader
	Handler  MessageHandler
}

// NewServer creates a WebSocket server
func NewServer(handler MessageHandler) *Server {
	return &Server{
		Upgrader: NewUpgrader(),
		Handler:  handler,
	}
}

// ServeHTTP handles HTTP requests and upgrades to WebSocket
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := s.Upgrader.Upgrade(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer conn.Close()

	for {
		messageType, data, err := conn.ReadMessage()
		if err != nil {
			break
		}

		// C1: Panic recovery per message
		func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("websocket: panic in handler", "err", r)
				}
			}()
			s.Handler(conn, messageType, data)
		}()
	}
}

// =============================================================================
// WebSocket Client
// =============================================================================

// Client represents a WebSocket client
type Client struct {
	URL       string
	Headers   map[string]string
	TLSConfig *tls.Config // H3: for wss:// connections
	conn      *Conn
	mu        sync.Mutex
}

// NewClient creates a WebSocket client
func NewClient(url string) *Client {
	return &Client{
		URL:     url,
		Headers: make(map[string]string),
	}
}

// Connect connects to WebSocket server
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		return errors.New("already connected")
	}

	// H3: Handle wss:// scheme
	var rawURL string
	var conn net.Conn
	var err error
	if strings.HasPrefix(c.URL, "wss://") {
		rawURL = strings.TrimPrefix(c.URL, "wss://")
		parts := strings.SplitN(rawURL, "/", 2)
		host := parts[0]
		tlsCfg := c.TLSConfig
		if tlsCfg == nil {
			tlsCfg = &tls.Config{}
		}
		conn, err = tls.Dial("tcp", host, tlsCfg)
		if err != nil {
			return fmt.Errorf("TLS connection failed: %w", err)
		}
	} else {
		// Parse URL (simplified - assumes ws://host:port/path)
		rawURL = strings.TrimPrefix(c.URL, "ws://")
		parts := strings.SplitN(rawURL, "/", 2)
		host := parts[0]
		conn, err = net.Dial("tcp", host)
		if err != nil {
			return fmt.Errorf("connection failed: %w", err)
		}
	}

	// Parse host and path from rawURL
	urlParts := strings.SplitN(rawURL, "/", 2)
	connHost := urlParts[0]
	connPath := "/"
	if len(urlParts) > 1 {
		connPath = "/" + urlParts[1]
	}

	// Generate a random WebSocket key per RFC 6455
	rawKey := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, rawKey); err != nil {
		conn.Close()
		return fmt.Errorf("failed to generate WebSocket key: %w", err)
	}
	key := base64.StdEncoding.EncodeToString(rawKey)

	request := fmt.Sprintf("GET %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\n"+
		"Sec-WebSocket-Version: 13\r\n\r\n",
		connPath, connHost, key)

	if _, err := conn.Write([]byte(request)); err != nil {
		conn.Close()
		return err
	}

	// Compute expected Sec-WebSocket-Accept per RFC 6455
	const magicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	h.Write([]byte(key + magicGUID))
	expectedAccept := base64.StdEncoding.EncodeToString(h.Sum(nil))

	// P5: Use bufio.Reader + http.ReadResponse to correctly parse the HTTP upgrade response,
	// even if it spans multiple TCP segments or exceeds a single Read buffer.
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to read upgrade response: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return fmt.Errorf("websocket: upgrade failed: status %d", resp.StatusCode)
	}
	gotAccept := resp.Header.Get("Sec-Websocket-Accept")
	if gotAccept != expectedAccept {
		conn.Close()
		return fmt.Errorf("websocket: invalid Sec-WebSocket-Accept: got %q want %q", gotAccept, expectedAccept)
	}

	// P5: If bufio.Reader has buffered bytes beyond the HTTP response, wrap the conn so
	// those bytes are consumed before any subsequent reads go to the underlying conn.
	var netConn net.Conn
	if br.Buffered() > 0 {
		netConn = &bufferedConn{Conn: conn, br: br}
	} else {
		netConn = conn
	}

	c.conn = NewConn(netConn, false)
	return nil
}

// bufferedConn wraps net.Conn, draining buffered bytes from a bufio.Reader first. (P5)
type bufferedConn struct {
	net.Conn
	br *bufio.Reader
}

func (bc *bufferedConn) Read(b []byte) (int, error) {
	return bc.br.Read(b)
}

// Send sends a message
func (c *Client) Send(data []byte) error {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()

	if conn == nil {
		return errors.New("not connected")
	}

	return conn.WriteBinary(data)
}

// Receive receives a message
func (c *Client) Receive() ([]byte, error) {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()

	if conn == nil {
		return nil, errors.New("not connected")
	}

	_, data, err := conn.ReadMessage()
	return data, err
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

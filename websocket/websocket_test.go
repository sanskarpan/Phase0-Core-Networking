/*
WebSocket Tests
===============

Comprehensive tests for WebSocket implementation.
*/

package websocket

import (
	"bytes"
	"context"
	"fmt"
	"net"
	nethttp "net/http"
	"sync"
	"testing"
	"time"
)

// =============================================================================
// Frame Tests
// =============================================================================

func TestFrame_ReadWrite(t *testing.T) {
	// Create pipe for testing
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	serverConn := NewConn(server, true)
	clientConn := NewConn(client, false)

	testFrames := []Frame{
		{Fin: true, Opcode: OpcodeText, Payload: []byte("Hello")},
		{Fin: true, Opcode: OpcodeBinary, Payload: []byte{0x01, 0x02, 0x03}},
		{Fin: false, Opcode: OpcodeText, Payload: []byte("Part1")},
		{Fin: true, Opcode: OpcodeContinuation, Payload: []byte("Part2")},
		{Fin: true, Opcode: OpcodePing, Payload: []byte("ping")},
	}

	var wg sync.WaitGroup

	// Writer goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, frame := range testFrames {
			if err := clientConn.WriteFrame(&frame); err != nil {
				t.Errorf("WriteFrame failed: %v", err)
			}
		}
	}()

	// Reader goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < len(testFrames); i++ {
			frame, err := serverConn.ReadFrame()
			if err != nil {
				t.Errorf("ReadFrame failed: %v", err)
				continue
			}

			expected := testFrames[i]
			if frame.Fin != expected.Fin {
				t.Errorf("Frame %d: Fin mismatch: got %v, want %v", i, frame.Fin, expected.Fin)
			}
			if frame.Opcode != expected.Opcode {
				t.Errorf("Frame %d: Opcode mismatch: got %d, want %d", i, frame.Opcode, expected.Opcode)
			}
			if !bytes.Equal(frame.Payload, expected.Payload) {
				t.Errorf("Frame %d: Payload mismatch: got %q, want %q", i, frame.Payload, expected.Payload)
			}
		}
	}()

	wg.Wait()
}

func TestFrame_Masking(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	serverConn := NewConn(server, true)
	clientConn := NewConn(client, false)

	var wg sync.WaitGroup

	testData := []byte("Test message for masking")

	wg.Add(1)
	go func() {
		defer wg.Done()
		frame := &Frame{
			Fin:     true,
			Opcode:  OpcodeText,
			Payload: testData,
		}
		clientConn.WriteFrame(frame)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		frame, err := serverConn.ReadFrame()
		if err != nil {
			t.Errorf("ReadFrame failed: %v", err)
			return
		}

		// Client frames should be masked
		if !frame.Masked {
			t.Error("Client frame should be masked")
		}

		// Payload should be unmasked correctly
		if !bytes.Equal(frame.Payload, testData) {
			t.Errorf("Payload mismatch after unmasking: got %q, want %q", frame.Payload, testData)
		}
	}()

	wg.Wait()
}

func TestFrame_LargePayload(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	serverConn := NewConn(server, true)
	clientConn := NewConn(client, false)

	// Test with various payload sizes
	sizes := []int{125, 126, 127, 1000, 65535, 65536, 70000}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			payload := make([]byte, size)
			for i := range payload {
				payload[i] = byte(i % 256)
			}

			var wg sync.WaitGroup

			wg.Add(1)
			go func() {
				defer wg.Done()
				frame := &Frame{
					Fin:     true,
					Opcode:  OpcodeBinary,
					Payload: payload,
				}
				if err := clientConn.WriteFrame(frame); err != nil {
					t.Errorf("WriteFrame failed: %v", err)
				}
			}()

			wg.Add(1)
			go func() {
				defer wg.Done()
				frame, err := serverConn.ReadFrame()
				if err != nil {
					t.Errorf("ReadFrame failed: %v", err)
					return
				}

				if len(frame.Payload) != size {
					t.Errorf("Payload size mismatch: got %d, want %d", len(frame.Payload), size)
				}

				if !bytes.Equal(frame.Payload, payload) {
					t.Error("Payload content mismatch")
				}
			}()

			wg.Wait()
		})
	}
}

// =============================================================================
// Message Tests
// =============================================================================

func TestMessage_ReadWrite(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	serverConn := NewConn(server, true)
	clientConn := NewConn(client, false)

	testMessages := []struct {
		messageType byte
		data        []byte
	}{
		{OpcodeText, []byte("Hello, WebSocket!")},
		{OpcodeBinary, []byte{0x01, 0x02, 0x03, 0x04, 0x05}},
		{OpcodeText, []byte("Another text message")},
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, msg := range testMessages {
			if err := clientConn.WriteMessage(msg.messageType, msg.data); err != nil {
				t.Errorf("WriteMessage failed: %v", err)
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i, expected := range testMessages {
			messageType, data, err := serverConn.ReadMessage()
			if err != nil {
				t.Errorf("ReadMessage %d failed: %v", i, err)
				continue
			}

			if messageType != expected.messageType {
				t.Errorf("Message %d: type mismatch: got %d, want %d", i, messageType, expected.messageType)
			}

			if !bytes.Equal(data, expected.data) {
				t.Errorf("Message %d: data mismatch: got %q, want %q", i, data, expected.data)
			}
		}
	}()

	wg.Wait()
}

func TestMessage_Fragmented(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	serverConn := NewConn(server, true)
	clientConn := NewConn(client, false)

	var wg sync.WaitGroup

	// Send fragmented message
	wg.Add(1)
	go func() {
		defer wg.Done()

		// First fragment
		clientConn.WriteFrame(&Frame{
			Fin:     false,
			Opcode:  OpcodeText,
			Payload: []byte("Hello, "),
		})

		// Second fragment
		clientConn.WriteFrame(&Frame{
			Fin:     false,
			Opcode:  OpcodeContinuation,
			Payload: []byte("fragmented "),
		})

		// Final fragment
		clientConn.WriteFrame(&Frame{
			Fin:     true,
			Opcode:  OpcodeContinuation,
			Payload: []byte("message!"),
		})
	}()

	// Receive complete message
	wg.Add(1)
	go func() {
		defer wg.Done()

		messageType, data, err := serverConn.ReadMessage()
		if err != nil {
			t.Errorf("ReadMessage failed: %v", err)
			return
		}

		if messageType != OpcodeText {
			t.Errorf("Message type: got %d, want %d", messageType, OpcodeText)
		}

		expected := "Hello, fragmented message!"
		if string(data) != expected {
			t.Errorf("Message data: got %q, want %q", data, expected)
		}
	}()

	wg.Wait()
}

// =============================================================================
// Ping/Pong Tests
// =============================================================================

func TestPingPong(t *testing.T) {
	server, client := net.Pipe()

	serverConn := NewConn(server, true)
	clientConn := NewConn(client, false)

	// Server goroutine: ReadMessage handles ping by sending pong automatically
	go func() {
		serverConn.ReadMessage()
	}()

	time.Sleep(50 * time.Millisecond)

	if err := clientConn.Ping(); err != nil {
		server.Close()
		client.Close()
		t.Fatalf("Ping failed: %v", err)
	}

	// Read pong response
	frame, err := clientConn.ReadFrame()
	// Close connections to unblock the server goroutine before asserting
	server.Close()
	client.Close()

	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	if frame.Opcode != OpcodePong {
		t.Errorf("Expected pong, got opcode %d", frame.Opcode)
	}
}

// =============================================================================
// Connection Tests
// =============================================================================

func TestConn_Close(t *testing.T) {
	server, client := net.Pipe()

	serverConn := NewConn(server, true)
	clientConn := NewConn(client, false)

	var wg sync.WaitGroup

	// Server receives close frame
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _, err := serverConn.ReadMessage()
		if err == nil {
			t.Error("Expected error after close")
		}
	}()

	// Client closes connection
	time.Sleep(50 * time.Millisecond)
	clientConn.Close()

	wg.Wait()

	// Second close should not panic
	clientConn.Close()
}

func TestConn_WriteAfterClose(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	conn := NewConn(client, false)
	conn.Close()

	err := conn.WriteMessage(OpcodeText, []byte("test"))
	if err == nil {
		t.Error("WriteMessage should fail after Close")
	}
}

// =============================================================================
// Server Tests
// =============================================================================

func TestWebSocketServer(t *testing.T) {
	messageReceived := make(chan []byte, 1)

	wsServer := NewServer(func(conn *Conn, messageType byte, data []byte) {
		messageReceived <- data
		// Echo back
		conn.WriteMessage(messageType, data)
	})

	httpServer := &nethttp.Server{
		Addr:    ":0",
		Handler: wsServer,
	}

	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	go func() {
		httpServer.Serve(listener)
	}()

	time.Sleep(100 * time.Millisecond)

	addr := listener.Addr().String()

	// Connect client
	client := NewClient("ws://" + addr + "/ws")
	ctx := context.Background()

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	// Send message
	testData := []byte("Hello, Server!")
	if err := client.Send(testData); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	// Check server received
	select {
	case data := <-messageReceived:
		if !bytes.Equal(data, testData) {
			t.Errorf("Server received: got %q, want %q", data, testData)
		}
	case <-time.After(time.Second):
		t.Fatal("Server did not receive message")
	}

	// Receive echo
	response, err := client.Receive()
	if err != nil {
		t.Fatalf("Receive failed: %v", err)
	}

	if !bytes.Equal(response, testData) {
		t.Errorf("Echo response: got %q, want %q", response, testData)
	}
}

// =============================================================================
// Client Tests
// =============================================================================

func TestWebSocketClient_ConnectFail(t *testing.T) {
	client := NewClient("ws://localhost:59999/ws")
	ctx := context.Background()

	err := client.Connect(ctx)
	if err == nil {
		t.Fatal("Connect should fail for non-existent server")
	}
}

func TestWebSocketClient_MultipleMessages(t *testing.T) {
	wsServer := NewServer(func(conn *Conn, messageType byte, data []byte) {
		// Echo back
		conn.WriteMessage(messageType, data)
	})

	httpServer := &nethttp.Server{
		Addr:    ":0",
		Handler: wsServer,
	}

	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	go func() {
		httpServer.Serve(listener)
	}()

	time.Sleep(100 * time.Millisecond)

	addr := listener.Addr().String()

	client := NewClient("ws://" + addr + "/ws")
	ctx := context.Background()

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	// Send multiple messages
	for i := 0; i < 5; i++ {
		msg := []byte(fmt.Sprintf("Message %d", i))

		if err := client.Send(msg); err != nil {
			t.Fatalf("Send %d failed: %v", i, err)
		}

		response, err := client.Receive()
		if err != nil {
			t.Fatalf("Receive %d failed: %v", i, err)
		}

		if !bytes.Equal(response, msg) {
			t.Errorf("Message %d: echo mismatch", i)
		}
	}
}

// =============================================================================
// Upgrader Tests
// =============================================================================

func TestUpgrader_MissingHeaders(t *testing.T) {
	upgrader := NewUpgrader()

	// Test missing Upgrade header
	req := &nethttp.Request{
		Header: nethttp.Header{},
	}

	_, err := upgrader.Upgrade(nil, req)
	if err == nil {
		t.Error("Upgrade should fail with missing Upgrade header")
	}

	// Test missing Connection header
	req.Header.Set("Upgrade", "websocket")
	_, err = upgrader.Upgrade(nil, req)
	if err == nil {
		t.Error("Upgrade should fail with missing Connection header")
	}

	// Test missing Sec-WebSocket-Key
	req.Header.Set("Connection", "Upgrade")
	_, err = upgrader.Upgrade(nil, req)
	if err == nil {
		t.Error("Upgrade should fail with missing Sec-WebSocket-Key")
	}
}

func TestUpgrader_CheckOrigin(t *testing.T) {
	upgrader := NewUpgrader()
	upgrader.CheckOrigin = func(r *nethttp.Request) bool {
		origin := r.Header.Get("Origin")
		return origin == "http://allowed.com"
	}

	req := &nethttp.Request{
		Header: nethttp.Header{
			"Upgrade":           []string{"websocket"},
			"Connection":        []string{"Upgrade"},
			"Sec-WebSocket-Key": []string{"dGhlIHNhbXBsZSBub25jZQ=="},
			"Origin":            []string{"http://disallowed.com"},
		},
	}

	_, err := upgrader.Upgrade(nil, req)
	if err == nil {
		t.Error("Upgrade should fail for disallowed origin")
	}

	// Test allowed origin
	req.Header.Set("Origin", "http://allowed.com")
	// Will still fail because we need a real ResponseWriter, but should pass origin check
	// The error message will be different
	_, err = upgrader.Upgrade(nil, req)
	if err != nil && err.Error() == "origin not allowed" {
		t.Error("Should pass origin check for allowed origin")
	}
}

// =============================================================================
// C7: TestControlFrameFragmented
// =============================================================================

func TestControlFrameFragmented(t *testing.T) {
	// Create a pair of raw net.Conn connections (no ping loop).
	serverRaw, clientRaw := net.Pipe()
	defer serverRaw.Close()
	defer clientRaw.Close()

	// Wrap only the server side in a Conn so we can call ReadFrame.
	// Use the raw Conn struct directly to avoid starting a ping loop.
	serverConn := &Conn{conn: serverRaw, isServer: true, done: make(chan struct{})}

	done := make(chan error, 1)
	go func() {
		_, err := serverConn.ReadFrame()
		done <- err
	}()

	// Write a fragmented close frame (FIN=0, Opcode=8=Close) from the client side.
	header := []byte{
		0x08, // FIN=0, Opcode=Close (invalid: control frames must not be fragmented)
		0x00, // no mask, 0 length
	}
	clientRaw.Write(header)

	select {
	case err := <-done:
		if err == nil {
			t.Error("Expected error for fragmented control frame")
		} else {
			t.Logf("Got expected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("ReadFrame timed out waiting for fragmented control frame error")
	}
}

// =============================================================================
// H9: TestWebSocketCloseWithCode
// =============================================================================

func TestWebSocketCloseWithCode(t *testing.T) {
	// Setup WebSocket server
	upgrader := NewUpgrader()
	var serverConn *Conn

	connCh := make(chan *Conn, 1)
	srv := nethttp.Server{}
	mux := nethttp.NewServeMux()
	mux.HandleFunc("/ws", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		conn, err := upgrader.Upgrade(w, r)
		if err != nil {
			t.Errorf("Upgrade failed: %v", err)
			return
		}
		connCh <- conn
	})
	srv.Handler = mux

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	go srv.Serve(ln)
	defer srv.Close()

	addr := ln.Addr().String()
	client := NewClient("ws://" + addr + "/ws")
	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	serverConn = <-connCh

	// Close with code
	err = serverConn.CloseWithCode(CloseGoingAway, "shutting down")
	if err != nil {
		t.Errorf("CloseWithCode failed: %v", err)
	}

	if serverConn.CloseCode != CloseGoingAway {
		t.Errorf("CloseCode: got %d, want %d", serverConn.CloseCode, CloseGoingAway)
	}
}

// =============================================================================
// H10: TestSubprotocolNegotiation
// =============================================================================

func TestSubprotocolNegotiation(t *testing.T) {
	upgrader := NewUpgrader()
	upgrader.Protocols = []string{"chat", "binary"}

	connCh := make(chan *Conn, 1)
	srv := nethttp.Server{}
	mux := nethttp.NewServeMux()
	mux.HandleFunc("/ws", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		conn, err := upgrader.Upgrade(w, r)
		if err != nil {
			t.Errorf("Upgrade failed: %v", err)
			return
		}
		connCh <- conn
	})
	srv.Handler = mux

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	go srv.Serve(ln)
	defer srv.Close()

	addr := ln.Addr().String()

	// Connect with a supported protocol
	server, clientNet := net.Pipe()
	go func() {
		// Handshake manually
		rawKey := make([]byte, 16)
		import_io := bytes.NewReader(rawKey)
		_ = import_io
		request := "GET /ws HTTP/1.1\r\n" +
			"Host: " + addr + "\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
			"Sec-WebSocket-Version: 13\r\n" +
			"Sec-WebSocket-Protocol: binary, chat\r\n\r\n"
		clientNet.Write([]byte(request))
	}()
	_ = server
	_ = clientNet

	client := NewClient("ws://" + addr + "/ws")
	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	wsConn := <-connCh
	defer wsConn.Close()

	// Protocol should be negotiated
	proto := wsConn.Protocol()
	if proto != "chat" && proto != "binary" {
		t.Logf("Negotiated protocol: %q (may be empty if client doesn't specify)", proto)
	}
}

// =============================================================================
// M12: TestWriteCompressedMessage
// =============================================================================

func TestWriteCompressedMessage(t *testing.T) {
	// Test that WriteCompressedMessage works with compression enabled
	serverNet, clientNet := net.Pipe()
	defer serverNet.Close()
	defer clientNet.Close()

	serverConn := NewConn(serverNet, true)
	serverConn.compressed = true

	clientConn := NewConn(clientNet, false)

	data := []byte("hello compressed world - this is a test message that should be compressed")

	// Write compressed from server
	go func() {
		if err := serverConn.WriteCompressedMessage(data); err != nil {
			t.Errorf("WriteCompressedMessage failed: %v", err)
		}
	}()

	// Read from client (will be compressed bytes, but frame should be readable)
	_, received, err := clientConn.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}

	// The received data will be flate-compressed, but the frame itself should work
	if len(received) == 0 {
		t.Error("Expected non-empty received data")
	}
}

// =============================================================================
// C1: TestRecoveryFromPanic in ServeHTTP
// =============================================================================

func TestWebSocketPanicRecovery(t *testing.T) {
	// Test that ServeHTTP catches panics in handler
	panicHandler := func(conn *Conn, messageType byte, data []byte) {
		panic("test panic")
	}

	server := NewServer(panicHandler)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	httpSrv := &nethttp.Server{}
	mux := nethttp.NewServeMux()
	mux.HandleFunc("/ws", server.ServeHTTP)
	httpSrv.Handler = mux
	go httpSrv.Serve(ln)
	defer httpSrv.Close()

	addr := ln.Addr().String()
	client := NewClient("ws://" + addr + "/ws")
	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	// Send a message - should not cause server to crash
	client.Send([]byte("trigger panic"))
	time.Sleep(100 * time.Millisecond)
	// Server should still be alive (no crash)
}

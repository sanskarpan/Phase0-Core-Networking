/*
TCP Tests
=========

Comprehensive tests for TCP socket programming implementation.
*/

package tcp

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Phase0_Core/Networking/security"
)

// =============================================================================
// Server Tests
// =============================================================================

func TestTCPServer_StartStop(t *testing.T) {
	server := NewServer(":0", EchoServer())

	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start()
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Check server is active
	if !server.IsActive() {
		t.Fatal("Server should be active after Start()")
	}

	// Stop server
	if err := server.Stop(); err != nil {
		t.Fatalf("Stop() failed: %v", err)
	}

	// Check server is inactive
	if server.IsActive() {
		t.Fatal("Server should be inactive after Stop()")
	}

	// Check Start() returned
	select {
	case err := <-errChan:
		if err != nil && err.Error() != "server stopped" {
			t.Fatalf("Unexpected error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Start() did not return after Stop()")
	}
}

func TestTCPServer_EchoHandler(t *testing.T) {
	server := NewServer(":0", EchoServer())

	go func() {
		server.Start()
	}()
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	// Get server address
	addr := server.GetListener().Addr().String()

	// Connect client
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	// Send data
	testData := []byte("Hello, Server!")
	if _, err := conn.Write(testData); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Receive echo
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if !bytes.Equal(buffer[:n], testData) {
		t.Fatalf("Echo mismatch: got %q, want %q", buffer[:n], testData)
	}
}

func TestTCPServer_MultipleConnections(t *testing.T) {
	server := NewServer(":0", EchoServer())

	go func() {
		server.Start()
	}()
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	addr := server.GetListener().Addr().String()

	// Connect multiple clients
	numClients := 10
	var wg sync.WaitGroup

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Errorf("Client %d: Dial failed: %v", id, err)
				return
			}
			defer conn.Close()

			testData := []byte(fmt.Sprintf("Message from client %d", id))
			if _, err := conn.Write(testData); err != nil {
				t.Errorf("Client %d: Write failed: %v", id, err)
				return
			}

			buffer := make([]byte, 1024)
			n, err := conn.Read(buffer)
			if err != nil {
				t.Errorf("Client %d: Read failed: %v", id, err)
				return
			}

			if !bytes.Equal(buffer[:n], testData) {
				t.Errorf("Client %d: Echo mismatch", id)
			}
		}(i)
	}

	wg.Wait()
	// Give server goroutines time to process connection closures and update stats.
	time.Sleep(100 * time.Millisecond)

	// Check statistics
	total, active, _, _ := server.GetStats()
	if total != int64(numClients) {
		t.Errorf("Total connections: got %d, want %d", total, numClients)
	}
	if active != 0 {
		t.Errorf("Active connections: got %d, want 0", active)
	}
}

func TestTCPServer_GetListener(t *testing.T) {
	server := NewServer(":0", EchoServer())

	// Should return nil before Start()
	if server.GetListener() != nil {
		t.Error("GetListener() should return nil before Start()")
	}

	go func() {
		server.Start()
	}()
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	// Should return listener after Start()
	if server.GetListener() == nil {
		t.Error("GetListener() should return listener after Start()")
	}
}

// =============================================================================
// Client Tests
// =============================================================================

func TestTCPClient_ConnectDisconnect(t *testing.T) {
	// Start test server
	server := NewServer(":0", EchoServer())
	go func() {
		server.Start()
	}()
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	addr := server.GetListener().Addr().String()

	// Test client
	client := NewClient(addr, 5*time.Second)

	// Connect
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	// Close
	if err := client.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Close again should not error
	if err := client.Close(); err != nil {
		t.Fatalf("Second Close failed: %v", err)
	}
}

func TestTCPClient_SendReceive(t *testing.T) {
	server := NewServer(":0", EchoServer())
	go func() {
		server.Start()
	}()
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	addr := server.GetListener().Addr().String()
	client := NewClient(addr, 5*time.Second)

	if err := client.Connect(); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	// Send data
	testData := []byte("Test message\n")
	if err := client.Send(testData); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	// Receive data
	buffer := make([]byte, 1024)
	n, err := client.Receive(buffer)
	if err != nil {
		t.Fatalf("Receive failed: %v", err)
	}

	if !bytes.Equal(buffer[:n], testData) {
		t.Fatalf("Data mismatch: got %q, want %q", buffer[:n], testData)
	}
}

func TestTCPClient_Timeout(t *testing.T) {
	// Try to connect to non-existent server
	client := NewClient("localhost:59999", 100*time.Millisecond)

	start := time.Now()
	err := client.Connect()
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Connect should fail for non-existent server")
	}

	// Should timeout quickly
	if elapsed > 500*time.Millisecond {
		t.Errorf("Timeout took too long: %v", elapsed)
	}
}

// =============================================================================
// Connection Pool Tests
// =============================================================================

func TestConnectionPool_GetPut(t *testing.T) {
	server := NewServer(":0", EchoServer())
	go func() {
		server.Start()
	}()
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	addr := server.GetListener().Addr().String()

	config := PoolConfig{
		MaxConnections: 5,
		MinConnections: 2,
		DialTimeout:    5 * time.Second,
		MaxIdleTime:    30 * time.Second,
	}

	pool, err := NewConnectionPool(addr, config)
	if err != nil {
		t.Fatalf("NewConnectionPool failed: %v", err)
	}
	defer pool.Close()

	// Get connection
	conn, err := pool.Get()
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	// Active connections should be 1
	if pool.ActiveConnections() != 1 {
		t.Errorf("ActiveConnections: got %d, want 1", pool.ActiveConnections())
	}

	// Put connection back
	if err := pool.Put(conn); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// After Put(), the connection is back in the pool and activeConn is decremented.
	// activeConn tracks checked-out connections only, so it returns to 0.
	time.Sleep(50 * time.Millisecond)
	if pool.ActiveConnections() != 0 {
		t.Errorf("ActiveConnections after Put: got %d, want 0", pool.ActiveConnections())
	}
}

func TestConnectionPool_MaxConnections(t *testing.T) {
	server := NewServer(":0", EchoServer())
	go func() {
		server.Start()
	}()
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	addr := server.GetListener().Addr().String()

	config := PoolConfig{
		MaxConnections: 3,
		MinConnections: 1,
		DialTimeout:    5 * time.Second,
		MaxIdleTime:    30 * time.Second,
	}

	pool, err := NewConnectionPool(addr, config)
	if err != nil {
		t.Fatalf("NewConnectionPool failed: %v", err)
	}
	defer pool.Close()

	// Get max connections
	conns := make([]net.Conn, 3)
	for i := 0; i < 3; i++ {
		conn, err := pool.Get()
		if err != nil {
			t.Fatalf("Get %d failed: %v", i, err)
		}
		conns[i] = conn
	}

	// Should have max active connections
	if pool.ActiveConnections() != 3 {
		t.Errorf("ActiveConnections: got %d, want 3", pool.ActiveConnections())
	}

	// Try to get another connection (should block or fail)
	done := make(chan bool)
	go func() {
		conn, err := pool.Get()
		if err == nil {
			pool.Put(conn)
		}
		done <- true
	}()

	// Put one back
	time.Sleep(100 * time.Millisecond)
	pool.Put(conns[0])

	// The blocked Get should now succeed
	select {
	case <-done:
		// Success
	case <-time.After(time.Second):
		t.Error("Get did not unblock after Put")
	}

	// Return remaining connections
	for i := 1; i < 3; i++ {
		pool.Put(conns[i])
	}
}

func TestConnectionPool_Close(t *testing.T) {
	server := NewServer(":0", EchoServer())
	go func() {
		server.Start()
	}()
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	addr := server.GetListener().Addr().String()

	config := PoolConfig{
		MaxConnections: 5,
		MinConnections: 2,
		DialTimeout:    5 * time.Second,
		MaxIdleTime:    30 * time.Second,
	}

	pool, err := NewConnectionPool(addr, config)
	if err != nil {
		t.Fatalf("NewConnectionPool failed: %v", err)
	}

	// Close pool
	pool.Close()

	// Get should fail after close
	_, err = pool.Get()
	if err == nil {
		t.Error("Get should fail after Close")
	}

	// Close again should not panic
	pool.Close()
}

// =============================================================================
// Frame Reader/Writer Tests
// =============================================================================

func TestFrameReadWrite(t *testing.T) {
	server := NewServer(":0", func(conn net.Conn) {
		reader := NewFrameReader(conn)
		writer := NewFrameWriter(conn)

		for {
			frame, err := reader.ReadFrame()
			if err != nil {
				return
			}
			writer.WriteFrame(frame)
		}
	})

	go func() {
		server.Start()
	}()
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	addr := server.GetListener().Addr().String()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	writer := NewFrameWriter(conn)
	reader := NewFrameReader(conn)

	// Test data
	testFrames := [][]byte{
		[]byte("Short message"),
		[]byte("A much longer message that spans multiple bytes to test the framing protocol"),
		[]byte(""),
		make([]byte, 1000), // Large frame
	}

	for i, data := range testFrames {
		// Write frame
		if err := writer.WriteFrame(data); err != nil {
			t.Fatalf("WriteFrame %d failed: %v", i, err)
		}

		// Read frame
		received, err := reader.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame %d failed: %v", i, err)
		}

		if !bytes.Equal(received, data) {
			t.Errorf("Frame %d mismatch: len(got)=%d, len(want)=%d", i, len(received), len(data))
		}
	}
}

// =============================================================================
// Keep-Alive Tests
// =============================================================================

func TestKeepAliveConn(t *testing.T) {
	server := NewServer(":0", EchoServer())
	go func() {
		server.Start()
	}()
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	addr := server.GetListener().Addr().String()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	// Wrap with keep-alive
	kaConn := NewKeepAliveConn(conn, 500*time.Millisecond)
	defer kaConn.Close()

	// Send/receive should work
	testData := []byte("Test\n")
	if _, err := kaConn.Write(testData); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	buffer := make([]byte, 1024)
	n, err := kaConn.Read(buffer)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if !bytes.Equal(buffer[:n], testData) {
		t.Error("Data mismatch")
	}

	// Connection should stay alive
	time.Sleep(200 * time.Millisecond)

	if _, err := kaConn.Write(testData); err != nil {
		t.Fatalf("Write after delay failed: %v", err)
	}
}

func TestKeepAliveConn_Timeout(t *testing.T) {
	server := NewServer(":0", func(conn net.Conn) {
		// Accept but don't respond
		buffer := make([]byte, 1024)
		conn.Read(buffer)
		time.Sleep(2 * time.Second)
	})

	go func() {
		server.Start()
	}()
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	addr := server.GetListener().Addr().String()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	// Short keep-alive timeout
	kaConn := NewKeepAliveConn(conn, 300*time.Millisecond)
	defer kaConn.Close()

	// Send data
	kaConn.Write([]byte("Test\n"))

	// Wait for timeout
	time.Sleep(500 * time.Millisecond)

	// Connection should be closed
	buffer := make([]byte, 1024)
	_, err = kaConn.Read(buffer)
	if err == nil {
		t.Error("Read should fail after keep-alive timeout")
	}
}

// =============================================================================
// Request-Response Client Tests
// =============================================================================

func TestRequestResponseClient(t *testing.T) {
	// Create echo server with framing
	server := NewServer(":0", func(conn net.Conn) {
		reader := NewFrameReader(conn)
		writer := NewFrameWriter(conn)

		for {
			frame, err := reader.ReadFrame()
			if err != nil {
				return
			}
			writer.WriteFrame(frame)
		}
	})

	go func() {
		server.Start()
	}()
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	addr := server.GetListener().Addr().String()

	// Connect first
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	client := NewRequestResponseClient(conn)
	defer client.Close()

	// Send request
	request := []byte("Hello, Server!")
	ctx := context.Background()
	response, err := client.SendRequest(ctx, request)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if !bytes.Equal(response, request) {
		t.Errorf("Response mismatch: got %q, want %q", response, request)
	}
}

func TestRequestResponseClient_MultipleRequests(t *testing.T) {
	server := NewServer(":0", func(conn net.Conn) {
		reader := NewFrameReader(conn)
		writer := NewFrameWriter(conn)

		for {
			frame, err := reader.ReadFrame()
			if err != nil {
				return
			}
			writer.WriteFrame(frame)
		}
	})

	go func() {
		server.Start()
	}()
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	addr := server.GetListener().Addr().String()

	// Connect first
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	client := NewRequestResponseClient(conn)
	defer client.Close()

	// Send multiple requests
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		request := []byte(fmt.Sprintf("Request %d", i))
		response, err := client.SendRequest(ctx, request)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}

		if !bytes.Equal(response, request) {
			t.Errorf("Request %d: response mismatch", i)
		}
	}
}

// =============================================================================
// New Feature Tests
// =============================================================================

// C2: TestRequestResponseContextCancel
func TestRequestResponseContextCancel(t *testing.T) {
	// Server that blocks forever
	server := NewServer(":0", func(conn net.Conn) {
		buf := make([]byte, 4096)
		conn.Read(buf) // Read the frame but never respond
		time.Sleep(5 * time.Second)
	})
	go func() { server.Start() }()
	defer server.Stop()
	time.Sleep(50 * time.Millisecond)

	addr := server.GetListener().Addr().String()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	client := NewRequestResponseClient(conn)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = client.SendRequest(ctx, []byte("hello"))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("took too long: %v", elapsed)
	}
}

// H1: TestTLSServerClient
func TestTLSServerClient(t *testing.T) {
	certPEM, keyPEM, err := security.GenerateSelfSignedCert(security.CertificateConfig{
		CommonName:  "localhost",
		Organization: "Test",
		ValidFor:    time.Hour,
		DNSNames:    []string{"localhost"},
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair failed: %v", err)
	}
	serverCfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	server := NewTLSServer(":0", func(conn net.Conn) {
		reader := NewFrameReader(conn)
		writer := NewFrameWriter(conn)
		for {
			frame, err := reader.ReadFrame()
			if err != nil {
				return
			}
			writer.WriteFrame(frame)
		}
	}, serverCfg)

	go func() { server.Start() }()
	defer server.Stop()
	time.Sleep(100 * time.Millisecond)

	addr := server.GetListener().Addr().String()

	clientCfg := &tls.Config{InsecureSkipVerify: true}
	client := NewClient(addr, 5*time.Second)
	if err := client.DialTLS(addr, clientCfg); err != nil {
		t.Fatalf("DialTLS failed: %v", err)
	}
	defer client.Close()

	// Use FrameReader/Writer through the underlying conn
	conn, _ := tls.Dial("tcp", addr, clientCfg)
	defer conn.Close()
	rrc := NewRequestResponseClient(conn)
	defer rrc.Close()

	resp, err := rrc.SendRequest(context.Background(), []byte("tls-test"))
	if err != nil {
		t.Fatalf("SendRequest failed: %v", err)
	}
	if !bytes.Equal(resp, []byte("tls-test")) {
		t.Errorf("response mismatch: got %q", resp)
	}
}

// M1: TestServerGracefulDrain
func TestServerGracefulDrain(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := NewServer(":0", func(conn net.Conn) {
		close(started)
		<-release
	})
	server.DrainTimeout = 500 * time.Millisecond

	go func() { server.Start() }()
	time.Sleep(50 * time.Millisecond)

	addr := server.GetListener().Addr().String()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	<-started // wait for handler to start

	stopDone := make(chan error, 1)
	go func() {
		stopDone <- server.Stop()
	}()

	time.Sleep(50 * time.Millisecond)
	close(release) // let handler finish

	select {
	case err := <-stopDone:
		if err != nil {
			t.Errorf("Stop returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Stop timed out")
	}
}

// M2: TestServerMaxConnections
func TestServerMaxConnections(t *testing.T) {
	server := NewServer(":0", func(conn net.Conn) {
		time.Sleep(300 * time.Millisecond)
	})
	server.MaxConnections = 2

	go func() { server.Start() }()
	defer server.Stop()
	time.Sleep(50 * time.Millisecond)

	addr := server.GetListener().Addr().String()

	// Connect 2 (should succeed)
	var conns []net.Conn
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("Dial %d failed: %v", i, err)
		}
		conns = append(conns, c)
	}
	time.Sleep(50 * time.Millisecond)

	// Third connection should be rejected
	c3, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial 3 failed: %v", err)
	}
	defer c3.Close()

	time.Sleep(100 * time.Millisecond)
	// Rejected counter should be > 0
	if atomic.LoadInt64(&server.RejectedConnections) < 1 {
		t.Error("Expected at least one rejected connection")
	}

	for _, c := range conns {
		c.Close()
	}
}

// M3: TestTCPNoDelay
func TestTCPNoDelay(t *testing.T) {
	server := NewServer(":0", EchoServer())
	go func() { server.Start() }()
	defer server.Stop()
	time.Sleep(50 * time.Millisecond)

	addr := server.GetListener().Addr().String()
	client := NewClient(addr, 5*time.Second)
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	// If we got here without error, TCP_NODELAY was set without panic
	testData := []byte("nodelay-test")
	if err := client.Send(testData); err != nil {
		t.Fatalf("Send failed: %v", err)
	}
}

// M4: TestCircuitBreaker
func TestCircuitBreaker(t *testing.T) {
	cb := NewCircuitBreaker(3, 100*time.Millisecond)

	// Initially closed, should allow
	if err := cb.Allow(); err != nil {
		t.Fatalf("Expected Allow() to pass: %v", err)
	}

	// Record failures to open
	cb.Failure()
	cb.Failure()
	cb.Failure()

	// Should be open now
	if err := cb.Allow(); err != ErrCircuitOpen {
		t.Errorf("Expected ErrCircuitOpen, got: %v", err)
	}

	// After recovery timeout, should be half-open
	time.Sleep(150 * time.Millisecond)
	if err := cb.Allow(); err != nil {
		t.Errorf("Expected Allow after recovery: %v", err)
	}

	// Success should close it
	cb.Success()
	if err := cb.Allow(); err != nil {
		t.Errorf("Expected Allow after success: %v", err)
	}
}

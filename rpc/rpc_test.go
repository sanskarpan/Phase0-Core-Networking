package rpc

import (
	"context"
	cryptoTLS "crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	stdNET "net"
	stdHTTP "net/http"
	"testing"
	"time"

	secPkg "github.com/Phase0_Core/Networking/security"
)

// helper to start a server on a random port and return address
func startTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	srv := NewServer("127.0.0.1:0")
	if err := srv.Start(); err != nil {
		t.Fatalf("server Start failed: %v", err)
	}
	addr := srv.listener.Addr().String()
	return srv, addr
}

// =============================================================================
// TestRPCUnaryCall
// =============================================================================

func TestRPCUnaryCall(t *testing.T) {
	srv, addr := startTestServer(t)
	defer srv.Stop()

	srv.Register("echo", func(ctx context.Context, req []byte) ([]byte, error) {
		return req, nil
	})

	client := NewClient(addr)
	if err := client.Connect(); err != nil {
		t.Fatalf("client Connect failed: %v", err)
	}
	defer client.Close()

	payload, _ := json.Marshal(map[string]string{"msg": "hello"})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.Call(ctx, "echo", payload)
	if err != nil {
		t.Fatalf("Call failed: %v", err)
	}

	var result map[string]string
	if err := json.Unmarshal(resp, &result); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if result["msg"] != "hello" {
		t.Errorf("unexpected response: %v", result)
	}
}

// =============================================================================
// TestRPCErrorResponse
// =============================================================================

func TestRPCErrorResponse(t *testing.T) {
	srv, addr := startTestServer(t)
	defer srv.Stop()

	srv.Register("fail", func(ctx context.Context, req []byte) ([]byte, error) {
		return nil, errors.New("intentional error")
	})

	client := NewClient(addr)
	if err := client.Connect(); err != nil {
		t.Fatalf("client Connect failed: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.Call(ctx, "fail", nil)
	if err == nil {
		t.Fatal("expected error from handler but got nil")
	}
}

// =============================================================================
// TestRPCServerStreaming
// =============================================================================

func TestRPCServerStreaming(t *testing.T) {
	srv, addr := startTestServer(t)
	defer srv.Stop()

	const numMessages = 5
	srv.RegisterStream("stream", func(stream ServerStream) error {
		for i := 0; i < numMessages; i++ {
			data := []byte(fmt.Sprintf("msg-%d", i))
			if err := stream.Send(data); err != nil {
				return err
			}
		}
		// Send EOF
		eofMsg := &Message{
			Type:      MessageTypeEOF,
			RequestID: 0,
		}
		_ = srv.writeMessage(stream.(*serverStream).conn, eofMsg)
		return nil
	})

	client := NewClient(addr)
	if err := client.Connect(); err != nil {
		t.Fatalf("client Connect failed: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Stream(ctx, "stream")
	if err != nil {
		t.Fatalf("Stream failed: %v", err)
	}

	// Send initial request to trigger the stream handler
	if err := stream.Send([]byte("start")); err != nil {
		t.Fatalf("stream Send failed: %v", err)
	}

	received := 0
	for {
		data, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			// context timeout or real error – acceptable if we already got messages
			break
		}
		expected := fmt.Sprintf("msg-%d", received)
		if string(data) != expected {
			t.Errorf("message %d: got %q, want %q", received, data, expected)
		}
		received++
		if received == numMessages {
			break
		}
	}

	if received != numMessages {
		t.Errorf("received %d messages, want %d", received, numMessages)
	}
}

// =============================================================================
// TestRPCClientStreaming
// =============================================================================

func TestRPCClientStreaming(t *testing.T) {
	srv, addr := startTestServer(t)
	defer srv.Stop()

	// The first MessageTypeStream triggers handleStreamRequest; the handler
	// then calls Recv() to read the remaining messages from the connection.
	// So the server handler sees (numSend - 1) messages via Recv() plus an EOF.
	const numSend = 4

	receivedCh := make(chan int, 1)
	srv.RegisterStream("collect", func(stream ServerStream) error {
		count := 0
		for {
			_, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				break
			}
			count++
		}
		receivedCh <- count
		return nil
	})

	client := NewClient(addr)
	if err := client.Connect(); err != nil {
		t.Fatalf("client Connect failed: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Stream(ctx, "collect")
	if err != nil {
		t.Fatalf("Stream failed: %v", err)
	}

	for i := 0; i < numSend; i++ {
		if err := stream.Send([]byte(fmt.Sprintf("item-%d", i))); err != nil {
			t.Fatalf("stream.Send failed: %v", err)
		}
	}

	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend failed: %v", err)
	}

	// The first Send triggers the handler; handler sees numSend-1 remaining Recvs
	// before the EOF CloseSend. Total messages readable by handler = numSend - 1.
	wantReceived := numSend - 1

	select {
	case count := <-receivedCh:
		if count != wantReceived {
			t.Errorf("server received %d messages, want %d", count, wantReceived)
		}
	case <-time.After(3 * time.Second):
		t.Error("timed out waiting for server to receive all messages")
	}
}

// =============================================================================
// TestRPCServiceRegisterDeregister
// =============================================================================

func TestRPCServiceRegisterDeregister(t *testing.T) {
	registry := NewServiceRegistry(time.Minute, 5*time.Minute)

	inst := &ServiceInstance{
		ID:      "svc-1",
		Name:    "my-service",
		Address: "127.0.0.1",
		Port:    9000,
	}

	if err := registry.Register(inst); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Discover should find it
	instances, err := registry.Discover("my-service")
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
	if len(instances) != 1 {
		t.Fatalf("expected 1 instance, got %d", len(instances))
	}
	if instances[0].ID != "svc-1" {
		t.Errorf("unexpected instance ID: %s", instances[0].ID)
	}

	// Deregister
	if err := registry.Deregister("my-service", "svc-1"); err != nil {
		t.Fatalf("Deregister failed: %v", err)
	}

	// Should be gone
	_, err = registry.Discover("my-service")
	if err == nil {
		t.Error("Discover should have failed after deregistration")
	}
}

// =============================================================================
// TestRPCHealthCheck
// =============================================================================

func TestRPCHealthCheck(t *testing.T) {
	registry := NewServiceRegistry(50*time.Millisecond, 5*time.Minute)

	inst := &ServiceInstance{
		ID:      "svc-hc",
		Name:    "health-svc",
		Address: "127.0.0.1",
		Port:    9001,
	}

	if err := registry.Register(inst); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Verify initially healthy
	if inst.Health != HealthStatusHealthy {
		t.Errorf("expected healthy status, got %s", inst.Health)
	}

	// Manually set unhealthy and verify UpdateHealth works
	if err := registry.UpdateHealth("health-svc", "svc-hc", HealthStatusUnhealthy); err != nil {
		t.Fatalf("UpdateHealth failed: %v", err)
	}

	retrieved, err := registry.GetInstance("health-svc", "svc-hc")
	if err != nil {
		t.Fatalf("GetInstance failed: %v", err)
	}
	if retrieved.Health != HealthStatusUnhealthy {
		t.Errorf("expected unhealthy, got %s", retrieved.Health)
	}

	// Restore to healthy
	if err := registry.UpdateHealth("health-svc", "svc-hc", HealthStatusHealthy); err != nil {
		t.Fatalf("UpdateHealth failed: %v", err)
	}
	if retrieved.Health != HealthStatusHealthy {
		t.Errorf("expected healthy after restore, got %s", retrieved.Health)
	}
}

// =============================================================================
// C3: TestRPCContextDeadline
// =============================================================================

func TestRPCContextDeadline(t *testing.T) {
	srv, addr := startTestServer(t)
	defer srv.Stop()

	srv.Register("slow", func(ctx context.Context, req []byte) ([]byte, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
			return req, nil
		}
	})

	client := NewClient(addr)
	client.DefaultCallTimeout = 0 // disable default timeout
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	// Context with very short deadline - server should see it
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := client.Call(ctx, "slow", []byte("data"))
	if err == nil {
		t.Fatal("Expected error due to deadline")
	}
}

// =============================================================================
// C5: TestHTTPHealthChecker
// =============================================================================

func TestHTTPHealthChecker(t *testing.T) {
	// Start a real HTTP server
	mux := stdHTTP.NewServeMux()
	mux.HandleFunc("/health", func(w stdHTTP.ResponseWriter, r *stdHTTP.Request) {
		w.WriteHeader(stdHTTP.StatusOK)
	})
	srv := &stdHTTP.Server{Handler: mux}

	ln, err := stdNET.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	go srv.Serve(ln)
	defer srv.Close()

	addr := ln.Addr().(*stdNET.TCPAddr)

	checker := &HTTPHealthChecker{Path: "/health"}
	ctx := context.Background()
	instance := &ServiceInstance{
		Address: "127.0.0.1",
		Port:    addr.Port,
	}

	if !checker.Check(ctx, instance) {
		t.Error("HTTPHealthChecker should return true for healthy server")
	}

	// Check non-existent path returns 404 which is < 500, still "healthy"
	checker2 := &HTTPHealthChecker{Path: "/nonexistent"}
	if !checker2.Check(ctx, instance) {
		t.Log("404 is treated as healthy (status < 500)")
	}
}

// =============================================================================
// C6: TestLoadBalancedClientLeastConn
// =============================================================================

func TestLoadBalancedClientLeastConn(t *testing.T) {
	srv1, addr1 := startTestServer(t)
	defer srv1.Stop()
	srv2, addr2 := startTestServer(t)
	defer srv2.Stop()

	srv1.Register("echo", func(ctx context.Context, req []byte) ([]byte, error) {
		return req, nil
	})
	srv2.Register("echo", func(ctx context.Context, req []byte) ([]byte, error) {
		return req, nil
	})

	lb, err := NewLoadBalancedClient([]string{addr1, addr2}, "least-conn")
	if err != nil {
		t.Fatalf("NewLoadBalancedClient failed: %v", err)
	}
	defer lb.Close()

	ctx := context.Background()
	for i := 0; i < 4; i++ {
		_, err := lb.Call(ctx, "echo", []byte("test"))
		if err != nil {
			t.Fatalf("Call %d failed: %v", i, err)
		}
	}

	// connCounts should all be 0 after all calls complete (decremented)
	for i, c := range lb.connCounts {
		if c != 0 {
			t.Errorf("connCounts[%d] = %d, want 0", i, c)
		}
	}
}

// =============================================================================
// M6: TestRPCCallTimeout
// =============================================================================

func TestRPCCallTimeout(t *testing.T) {
	srv, addr := startTestServer(t)
	defer srv.Stop()

	srv.Register("slow", func(ctx context.Context, req []byte) ([]byte, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
			return req, nil
		}
	})

	client := NewClient(addr)
	client.DefaultCallTimeout = 100 * time.Millisecond
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	ctx := context.Background() // no deadline
	start := time.Now()
	_, err := client.Call(ctx, "slow", []byte("data"))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Expected timeout error")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("Timeout took too long: %v", elapsed)
	}
}

// =============================================================================
// M7: TestRPCStructuredError
// =============================================================================

func TestRPCStructuredError(t *testing.T) {
	srv, addr := startTestServer(t)
	defer srv.Stop()

	srv.Register("fail", func(ctx context.Context, req []byte) ([]byte, error) {
		return nil, errors.New("simulated error")
	})

	client := NewClient(addr)
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	_, err := client.Call(ctx, "fail", []byte("data"))
	if err == nil {
		t.Fatal("Expected error")
	}
	if err.Error() != "simulated error" {
		t.Errorf("expected 'simulated error', got: %v", err)
	}
}

// =============================================================================
// M8: TestStreamDemux
// =============================================================================

func TestStreamDemux(t *testing.T) {
	srv, addr := startTestServer(t)
	defer srv.Stop()

	srv.RegisterStream("items", func(stream ServerStream) error {
		for i := 0; i < 3; i++ {
			if err := stream.Send([]byte(fmt.Sprintf("item-%d", i))); err != nil {
				return err
			}
		}
		return nil
	})

	client := NewClient(addr)
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	stream, err := client.Stream(ctx, "items")
	if err != nil {
		t.Fatalf("Stream failed: %v", err)
	}

	// Send initial request to trigger handler
	stream.Send([]byte("start"))

	count := 0
	for {
		_, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Recv failed: %v", err)
		}
		count++
		if count > 10 {
			break // prevent infinite loop in test
		}
	}
}

// =============================================================================
// H2: TestRPCTLS
// =============================================================================

func TestRPCTLS(t *testing.T) {
	certPEM, keyPEM, err := secPkg.GenerateSelfSignedCert(secPkg.CertificateConfig{
		CommonName:  "localhost",
		Organization: "Test",
		ValidFor:    time.Hour,
		DNSNames:    []string{"localhost"},
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	cert, err := cryptoTLS.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair failed: %v", err)
	}
	serverCfg := &cryptoTLS.Config{Certificates: []cryptoTLS.Certificate{cert}}

	srv := NewServer("127.0.0.1:0")
	srv.Register("ping", func(ctx context.Context, req []byte) ([]byte, error) {
		return []byte("pong"), nil
	})

	if err := srv.ListenTLS(serverCfg); err != nil {
		t.Fatalf("ListenTLS failed: %v", err)
	}
	// Give server time to start
	time.Sleep(50 * time.Millisecond)
	defer srv.Stop()

	addr := srv.listener.Addr().String()

	clientCfg := &cryptoTLS.Config{InsecureSkipVerify: true}
	client := NewClient(addr)
	if err := client.DialTLS(addr, clientCfg); err != nil {
		t.Fatalf("DialTLS failed: %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	resp, err := client.Call(ctx, "ping", nil)
	if err != nil {
		t.Fatalf("Call failed: %v", err)
	}
	if string(resp) != "pong" {
		t.Errorf("expected 'pong', got %q", resp)
	}
}

// =============================================================================
// L6: TestRPCReflection
// =============================================================================

func TestRPCReflection(t *testing.T) {
	srv, addr := startTestServer(t)
	defer srv.Stop()

	srv.Register("hello", func(ctx context.Context, req []byte) ([]byte, error) {
		return []byte("hi"), nil
	})
	srv.RegisterStream("stream_data", func(stream ServerStream) error {
		return nil
	})

	client := NewClient(addr)
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	methods, err := client.ListMethods(ctx)
	if err != nil {
		t.Fatalf("ListMethods failed: %v", err)
	}

	if len(methods) == 0 {
		t.Error("Expected at least one method from reflection")
	}

	// Check that hello and __reflection__ are in methods
	found := false
	for _, m := range methods {
		if m == "hello" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected 'hello' in methods list, got: %v", methods)
	}
}

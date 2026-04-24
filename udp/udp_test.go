/*
UDP Tests
=========

Comprehensive tests for UDP socket programming implementation.
*/

package udp

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// =============================================================================
// Server Tests
// =============================================================================

func TestUDPServer_StartStop(t *testing.T) {
	server := NewServer(":0", nil)
	server.Handler = EchoServer(server)

	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start()
	}()

	time.Sleep(100 * time.Millisecond)

	if !server.IsActive() {
		t.Fatal("Server should be active after Start()")
	}

	if err := server.Stop(); err != nil {
		t.Fatalf("Stop() failed: %v", err)
	}

	if server.IsActive() {
		t.Fatal("Server should be inactive after Stop()")
	}

	select {
	case err := <-errChan:
		if err != nil && err.Error() != "server stopped" {
			t.Fatalf("Unexpected error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Start() did not return after Stop()")
	}
}

func TestUDPServer_EchoHandler(t *testing.T) {
	server := NewServer(":0", nil)
	server.Handler = EchoServer(server)

	go func() {
		server.Start()
	}()
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	addr := server.GetConn().LocalAddr().String()

	// Create client connection
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	// Send data
	testData := []byte("Hello, UDP Server!")
	if _, err := conn.Write(testData); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Receive echo
	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	n, err := conn.Read(buffer)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if !bytes.Equal(buffer[:n], testData) {
		t.Fatalf("Echo mismatch: got %q, want %q", buffer[:n], testData)
	}
}

func TestUDPServer_MultipleClients(t *testing.T) {
	server := NewServer(":0", nil)
	server.Handler = EchoServer(server)

	go func() {
		server.Start()
	}()
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	addr := server.GetConn().LocalAddr().String()

	numClients := 10
	var wg sync.WaitGroup

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			conn, err := net.Dial("udp", addr)
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
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
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

	// Check statistics
	packetsRx, packetsTx, _, _ := server.GetStats()
	if packetsRx != int64(numClients) {
		t.Errorf("Packets received: got %d, want %d", packetsRx, numClients)
	}
	if packetsTx != int64(numClients) {
		t.Errorf("Packets sent: got %d, want %d", packetsTx, numClients)
	}
}

func TestUDPServer_GetConn(t *testing.T) {
	server := NewServer(":0", nil)

	if server.GetConn() != nil {
		t.Error("GetConn() should return nil before Start()")
	}

	go func() {
		server.Start()
	}()
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	if server.GetConn() == nil {
		t.Error("GetConn() should return connection after Start()")
	}
}

// =============================================================================
// Client Tests
// =============================================================================

func TestUDPClient_ConnectDisconnect(t *testing.T) {
	server := NewServer(":0", nil)
	server.Handler = EchoServer(server)

	go func() {
		server.Start()
	}()
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	addr := server.GetConn().LocalAddr().String()

	client := NewClient(addr, 5*time.Second)

	if err := client.Connect(); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	if err := client.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Close again should not error
	if err := client.Close(); err != nil {
		t.Fatalf("Second Close failed: %v", err)
	}
}

func TestUDPClient_Send(t *testing.T) {
	server := NewServer(":0", nil)
	received := make(chan []byte, 1)
	server.Handler = func(addr *net.UDPAddr, data []byte) {
		received <- data
	}

	go func() {
		server.Start()
	}()
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	addr := server.GetConn().LocalAddr().String()
	client := NewClient(addr, 5*time.Second)

	if err := client.Connect(); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	testData := []byte("Test message")
	if err := client.Send(testData); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	select {
	case data := <-received:
		if !bytes.Equal(data, testData) {
			t.Errorf("Data mismatch: got %q, want %q", data, testData)
		}
	case <-time.After(time.Second):
		t.Fatal("Server did not receive data")
	}
}

func TestUDPClient_SendReceive(t *testing.T) {
	server := NewServer(":0", nil)
	server.Handler = EchoServer(server)

	go func() {
		server.Start()
	}()
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	addr := server.GetConn().LocalAddr().String()
	client := NewClient(addr, 5*time.Second)

	if err := client.Connect(); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	testData := []byte("Test message")
	buffer := make([]byte, 1024)

	n, err := client.SendReceive(testData, buffer)
	if err != nil {
		t.Fatalf("SendReceive failed: %v", err)
	}

	if !bytes.Equal(buffer[:n], testData) {
		t.Fatalf("Data mismatch: got %q, want %q", buffer[:n], testData)
	}
}

func TestUDPClient_Timeout(t *testing.T) {
	// Server that doesn't respond
	server := NewServer(":0", func(addr *net.UDPAddr, data []byte) {
		// Do nothing
	})

	go func() {
		server.Start()
	}()
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	addr := server.GetConn().LocalAddr().String()
	client := NewClient(addr, 200*time.Millisecond)

	if err := client.Connect(); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	testData := []byte("Test")
	buffer := make([]byte, 1024)

	start := time.Now()
	_, err := client.SendReceive(testData, buffer)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("SendReceive should timeout")
	}

	if elapsed < 100*time.Millisecond || elapsed > 500*time.Millisecond {
		t.Errorf("Timeout duration unexpected: %v", elapsed)
	}
}

// =============================================================================
// Multicast Tests
// =============================================================================

func TestMulticastServer(t *testing.T) {
	// Note: Multicast tests may fail in some environments
	// This is a basic test
	multicastAddr := "224.0.0.1:9999"

	received := make(chan []byte, 1)
	server := NewMulticastServer(multicastAddr, "", func(addr *net.UDPAddr, data []byte) {
		received <- data
	})

	if err := server.Join(); err != nil {
		t.Skipf("Multicast not supported: %v", err)
	}
	defer server.Leave()

	time.Sleep(100 * time.Millisecond)

	// Send to multicast group
	conn, err := net.Dial("udp", multicastAddr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	testData := []byte("Multicast message")
	if _, err := conn.Write(testData); err != nil {
		t.Skipf("Multicast write not supported in this environment: %v", err)
	}

	select {
	case data := <-received:
		if !bytes.Equal(data, testData) {
			t.Errorf("Data mismatch: got %q, want %q", data, testData)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Did not receive multicast message")
	}
}

// =============================================================================
// Broadcast Tests
// =============================================================================

func TestBroadcastClient(t *testing.T) {
	// Listen for broadcast
	server := NewServer(":9998", nil)
	received := make(chan []byte, 1)
	server.Handler = func(addr *net.UDPAddr, data []byte) {
		received <- data
	}

	go func() {
		server.Start()
	}()
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	// Create broadcast client
	client := NewBroadcastClient(9998)
	if err := client.Open(); err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer client.Close()

	testData := []byte("Broadcast message")
	if err := client.Broadcast(testData); err != nil {
		t.Skipf("Broadcast not supported in this environment: %v", err)
	}

	select {
	case data := <-received:
		if !bytes.Equal(data, testData) {
			t.Errorf("Data mismatch: got %q, want %q", data, testData)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Did not receive broadcast message")
	}
}

// =============================================================================
// Reliable UDP Tests
// =============================================================================

func TestReliableUDP_SendReceive(t *testing.T) {
	// Create server that sends ACKs
	serverAddr := "127.0.0.1:0"
	serverConn, err := net.ListenPacket("udp4", serverAddr)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer serverConn.Close()

	addr := serverConn.LocalAddr().String()

	// Server goroutine - echoes sequence number as ACK
	go func() {
		buffer := make([]byte, 1024)
		for {
			n, clientAddr, err := serverConn.ReadFrom(buffer)
			if err != nil {
				return
			}

			// Extract sequence number (first 4 bytes) and send as ACK
			if n >= 4 {
				ackPacket := make([]byte, 5)
				ackPacket[0] = 1 // ACK flag
				copy(ackPacket[1:5], buffer[:4])
				serverConn.WriteTo(ackPacket, clientAddr)
			}
		}
	}()

	// Create reliable UDP client
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("ResolveUDPAddr failed: %v", err)
	}

	clientConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Client listen failed: %v", err)
	}
	defer clientConn.Close()

	udpConn := clientConn.(*net.UDPConn)
	reliable := NewReliableUDP(udpConn, udpAddr, 500*time.Millisecond, 3)

	ctx := context.Background()
	testData := []byte("Reliable message")

	if err := reliable.SendReliable(ctx, testData); err != nil {
		t.Fatalf("SendReliable failed: %v", err)
	}
}

func TestReliableUDP_Retry(t *testing.T) {
	// Server that drops first packet, responds to second
	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer serverConn.Close()

	addr := serverConn.LocalAddr().String()

	packetCount := 0
	var mu sync.Mutex

	go func() {
		buffer := make([]byte, 1024)
		for {
			n, clientAddr, err := serverConn.ReadFrom(buffer)
			if err != nil {
				return
			}

			mu.Lock()
			packetCount++
			shouldRespond := packetCount > 1
			mu.Unlock()

			if shouldRespond && n >= 4 {
				ackPacket := make([]byte, 5)
				ackPacket[0] = 1
				copy(ackPacket[1:5], buffer[:4])
				serverConn.WriteTo(ackPacket, clientAddr)
			}
		}
	}()

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("ResolveUDPAddr failed: %v", err)
	}

	clientConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Client listen failed: %v", err)
	}
	defer clientConn.Close()

	udpConn := clientConn.(*net.UDPConn)
	reliable := NewReliableUDP(udpConn, udpAddr, 200*time.Millisecond, 3)

	ctx := context.Background()
	testData := []byte("Retry test")

	if err := reliable.SendReliable(ctx, testData); err != nil {
		t.Fatalf("SendReliable failed: %v", err)
	}

	mu.Lock()
	count := packetCount
	mu.Unlock()

	// Should have retried at least once
	if count < 2 {
		t.Errorf("Expected retries, got %d packets", count)
	}
}

func TestReliableUDP_MaxRetries(t *testing.T) {
	// Server that never responds
	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer serverConn.Close()

	addr := serverConn.LocalAddr().String()

	go func() {
		buffer := make([]byte, 1024)
		for {
			_, _, err := serverConn.ReadFrom(buffer)
			if err != nil {
				return
			}
			// Don't respond
		}
	}()

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("ResolveUDPAddr failed: %v", err)
	}

	clientConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Client listen failed: %v", err)
	}
	defer clientConn.Close()

	udpConn := clientConn.(*net.UDPConn)
	reliable := NewReliableUDP(udpConn, udpAddr, 100*time.Millisecond, 2)

	ctx := context.Background()
	testData := []byte("Will fail")

	start := time.Now()
	err = reliable.SendReliable(ctx, testData)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("SendReliable should fail after max retries")
	}

	// Should take approximately maxRetries * timeout
	expectedMin := 150 * time.Millisecond
	expectedMax := 400 * time.Millisecond
	if elapsed < expectedMin || elapsed > expectedMax {
		t.Errorf("Retry duration unexpected: %v (expected between %v and %v)", elapsed, expectedMin, expectedMax)
	}
}

// =============================================================================
// L9: UDPv6 Server Tests
// =============================================================================

func TestUDPv6Server(t *testing.T) {
	server := NewServer(":0", nil)
	server.Handler = EchoServer(server)

	err := server.ListenIPv6("[::1]:0")
	if err != nil {
		t.Skipf("IPv6 not available: %v", err)
	}
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	addr := server.GetConn().LocalAddr().String()

	conn, err := net.Dial("udp6", addr)
	if err != nil {
		t.Skipf("Cannot connect to IPv6 server: %v", err)
	}
	defer conn.Close()

	testData := []byte("hello ipv6")
	if _, err := conn.Write(testData); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	buf := make([]byte, 64)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if string(buf[:n]) != string(testData) {
		t.Errorf("Echo mismatch: got %q want %q", buf[:n], testData)
	}
}

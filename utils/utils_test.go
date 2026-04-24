/*
Utils Tests
===========

Comprehensive tests for network utilities.
*/

package utils

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// =============================================================================
// DNS Resolver Tests
// =============================================================================

func TestDNSResolver_LookupIP(t *testing.T) {
	resolver := NewDNSResolver(5 * time.Second)

	// Lookup localhost
	ips, err := resolver.LookupIP("localhost")
	if err != nil {
		t.Fatalf("LookupIP failed: %v", err)
	}

	if len(ips) == 0 {
		t.Error("Expected at least one IP address")
	}

	// Check for loopback
	hasLoopback := false
	for _, ip := range ips {
		if ip.IsLoopback() {
			hasLoopback = true
			break
		}
	}

	if !hasLoopback {
		t.Error("Expected loopback IP for localhost")
	}
}

func TestDNSResolver_Cache(t *testing.T) {
	resolver := NewDNSResolver(5 * time.Second)

	// First lookup
	start := time.Now()
	ips1, err := resolver.LookupIP("localhost")
	elapsed1 := time.Since(start)

	if err != nil {
		t.Fatalf("First lookup failed: %v", err)
	}

	// Second lookup (should use cache)
	start = time.Now()
	ips2, err := resolver.LookupIP("localhost")
	elapsed2 := time.Since(start)

	if err != nil {
		t.Fatalf("Second lookup failed: %v", err)
	}

	// Cached lookup should be faster
	if elapsed2 >= elapsed1 {
		t.Logf("Warning: Cached lookup not faster (uncached: %v, cached: %v)", elapsed1, elapsed2)
	}

	// IPs should match
	if len(ips1) != len(ips2) {
		t.Errorf("IP count mismatch: first=%d, second=%d", len(ips1), len(ips2))
	}
}

func TestDNSResolver_ClearCache(t *testing.T) {
	resolver := NewDNSResolver(5 * time.Second)

	// Populate cache
	resolver.LookupIP("localhost")

	// Clear cache
	resolver.ClearCache()

	// Cache should be empty (we can't directly test this, but we can verify it doesn't crash)
	_, err := resolver.LookupIP("localhost")
	if err != nil {
		t.Fatalf("Lookup after cache clear failed: %v", err)
	}
}

func TestDNSResolver_InvalidHost(t *testing.T) {
	resolver := NewDNSResolver(time.Second)

	_, err := resolver.LookupIP("this-host-should-not-exist-12345.invalid")
	if err == nil {
		t.Error("Expected error for invalid hostname")
	}
}

func TestDNSResolver_LookupHost(t *testing.T) {
	resolver := NewDNSResolver(5 * time.Second)

	// Reverse lookup for loopback
	names, err := resolver.LookupHost("127.0.0.1")
	if err != nil {
		t.Skipf("Reverse lookup failed (may not be configured): %v", err)
	}

	if len(names) == 0 {
		t.Error("Expected at least one hostname")
	}
}

// =============================================================================
// Port Scanner Tests
// =============================================================================

func TestPortScanner_ScanPort(t *testing.T) {
	scanner := NewPortScanner(time.Second, 10)

	// Start a test server
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	port := addr.Port

	// Port should be open
	if !scanner.ScanPort("localhost", port) {
		t.Errorf("Port %d should be open", port)
	}

	// Random high port should be closed
	if scanner.ScanPort("localhost", 59999) {
		t.Error("Port 59999 should be closed")
	}
}

func TestPortScanner_ScanRange(t *testing.T) {
	scanner := NewPortScanner(100*time.Millisecond, 10)

	// Start multiple test servers
	listeners := make([]net.Listener, 3)
	expectedPorts := make(map[int]bool)

	for i := 0; i < 3; i++ {
		listener, err := net.Listen("tcp", ":0")
		if err != nil {
			t.Fatalf("Listen %d failed: %v", i, err)
		}
		defer listener.Close()

		port := listener.Addr().(*net.TCPAddr).Port
		listeners[i] = listener
		expectedPorts[port] = true
	}

	// Scan a range that includes our ports
	openPorts := scanner.ScanRange("localhost", 1024, 65535)

	// Check that our ports were found
	for port := range expectedPorts {
		found := false
		for _, p := range openPorts {
			if p == port {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Port %d not found in scan results", port)
		}
	}
}

func TestPortScanner_Timeout(t *testing.T) {
	scanner := NewPortScanner(50*time.Millisecond, 10)

	// Scan non-existent host
	start := time.Now()
	result := scanner.ScanPort("192.0.2.1", 80) // TEST-NET-1, should timeout
	elapsed := time.Since(start)

	if result {
		t.Error("Should not be able to connect to TEST-NET-1")
	}

	// Should timeout quickly
	if elapsed > 200*time.Millisecond {
		t.Errorf("Timeout took too long: %v", elapsed)
	}
}

// =============================================================================
// Load Balancer Tests
// =============================================================================

func TestLoadBalancer_RoundRobin(t *testing.T) {
	lb := NewLoadBalancer(RoundRobin)

	backends := []string{"server1:8080", "server2:8080", "server3:8080"}
	for _, addr := range backends {
		lb.AddBackend(addr, 1)
	}

	// Get backends in round-robin order
	seen := make(map[string]int)
	for i := 0; i < 9; i++ {
		backend, err := lb.GetBackend("192.168.1.1")
		if err != nil {
			t.Fatalf("GetBackend failed: %v", err)
		}
		seen[backend.Address]++
	}

	// Each backend should be selected 3 times
	for _, addr := range backends {
		if seen[addr] != 3 {
			t.Errorf("Backend %s: got %d selections, want 3", addr, seen[addr])
		}
	}
}

func TestLoadBalancer_LeastConnections(t *testing.T) {
	lb := NewLoadBalancer(LeastConnections)

	lb.AddBackend("server1:8080", 1)
	lb.AddBackend("server2:8080", 1)
	lb.AddBackend("server3:8080", 1)

	// Increment connections for server1
	lb.Backends[0].IncrementConnections()
	lb.Backends[0].IncrementConnections()

	// Increment connections for server2
	lb.Backends[1].IncrementConnections()

	// Server3 should be selected (0 connections)
	backend, err := lb.GetBackend("192.168.1.1")
	if err != nil {
		t.Fatalf("GetBackend failed: %v", err)
	}

	if backend.Address != "server3:8080" {
		t.Errorf("Expected server3, got %s", backend.Address)
	}
}

func TestLoadBalancer_IPHash(t *testing.T) {
	lb := NewLoadBalancer(IPHash)

	lb.AddBackend("server1:8080", 1)
	lb.AddBackend("server2:8080", 1)
	lb.AddBackend("server3:8080", 1)

	// Same IP should always get same backend
	ip := "192.168.1.100"

	backend1, _ := lb.GetBackend(ip)
	backend2, _ := lb.GetBackend(ip)
	backend3, _ := lb.GetBackend(ip)

	if backend1.Address != backend2.Address || backend2.Address != backend3.Address {
		t.Error("IP hash should return same backend for same IP")
	}

	// Different IP should potentially get different backend
	backend4, _ := lb.GetBackend("192.168.1.200")
	// May or may not be different, just verify it works
	_ = backend4
}

func TestLoadBalancer_AddRemoveBackend(t *testing.T) {
	lb := NewLoadBalancer(RoundRobin)

	lb.AddBackend("server1:8080", 1)
	lb.AddBackend("server2:8080", 1)

	if len(lb.Backends) != 2 {
		t.Errorf("Backend count: got %d, want 2", len(lb.Backends))
	}

	lb.RemoveBackend("server1:8080")

	if len(lb.Backends) != 1 {
		t.Errorf("Backend count after remove: got %d, want 1", len(lb.Backends))
	}

	backend, _ := lb.GetBackend("192.168.1.1")
	if backend.Address != "server2:8080" {
		t.Errorf("Remaining backend: got %s, want server2:8080", backend.Address)
	}
}

func TestLoadBalancer_MarkBackendDownUp(t *testing.T) {
	lb := NewLoadBalancer(RoundRobin)

	lb.AddBackend("server1:8080", 1)
	lb.AddBackend("server2:8080", 1)

	// Mark server1 down
	lb.MarkBackendDown("server1:8080")

	// Should only get server2
	for i := 0; i < 5; i++ {
		backend, err := lb.GetBackend("192.168.1.1")
		if err != nil {
			t.Fatalf("GetBackend failed: %v", err)
		}
		if backend.Address != "server2:8080" {
			t.Errorf("Expected server2, got %s", backend.Address)
		}
	}

	// Mark server1 up
	lb.MarkBackendUp("server1:8080")

	// Should now get both servers
	seen := make(map[string]bool)
	for i := 0; i < 10; i++ {
		backend, _ := lb.GetBackend("192.168.1.1")
		seen[backend.Address] = true
	}

	if !seen["server1:8080"] || !seen["server2:8080"] {
		t.Error("Both backends should be selected after marking up")
	}
}

func TestLoadBalancer_NoBackends(t *testing.T) {
	lb := NewLoadBalancer(RoundRobin)

	_, err := lb.GetBackend("192.168.1.1")
	if err == nil {
		t.Error("GetBackend should fail with no backends")
	}
}

// =============================================================================
// Connection Checker Tests
// =============================================================================

func TestCheckConnection(t *testing.T) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	// Connection should succeed
	if !CheckConnection(addr, time.Second) {
		t.Error("CheckConnection should succeed for listening port")
	}

	// Connection to closed port should fail
	listener.Close()
	time.Sleep(50 * time.Millisecond)

	if CheckConnection(addr, 100*time.Millisecond) {
		t.Error("CheckConnection should fail for closed port")
	}
}

func TestWaitForConnection(t *testing.T) {
	// Start server after delay
	go func() {
		time.Sleep(200 * time.Millisecond)
		listener, _ := net.Listen("tcp", ":19876")
		time.Sleep(500 * time.Millisecond)
		listener.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := WaitForConnection(ctx, "localhost:19876", 50*time.Millisecond)
	if err != nil {
		t.Fatalf("WaitForConnection failed: %v", err)
	}
}

func TestWaitForConnection_Timeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err := WaitForConnection(ctx, "localhost:59998", 50*time.Millisecond)
	if err == nil {
		t.Error("WaitForConnection should timeout")
	}

	if err != context.DeadlineExceeded {
		t.Errorf("Expected DeadlineExceeded, got %v", err)
	}
}

// =============================================================================
// Network Interface Tests
// =============================================================================

func TestGetLocalIP(t *testing.T) {
	ip, err := GetLocalIP()
	if err != nil {
		t.Fatalf("GetLocalIP failed: %v", err)
	}

	if ip == "" {
		t.Error("GetLocalIP returned empty string")
	}

	// Should be valid IP
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		t.Errorf("GetLocalIP returned invalid IP: %s", ip)
	}

	// Should not be loopback
	if parsedIP.IsLoopback() {
		t.Error("GetLocalIP should not return loopback address")
	}
}

func TestGetAllLocalIPs(t *testing.T) {
	ips, err := GetAllLocalIPs()
	if err != nil {
		t.Fatalf("GetAllLocalIPs failed: %v", err)
	}

	if len(ips) == 0 {
		t.Error("GetAllLocalIPs returned no IPs")
	}

	// All should be valid IPv4 addresses
	for _, ip := range ips {
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			t.Errorf("Invalid IP: %s", ip)
		}

		if parsedIP.To4() == nil {
			t.Errorf("Not IPv4: %s", ip)
		}
	}
}

func TestIsPortAvailable(t *testing.T) {
	// Find a free port
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	port := listener.Addr().(*net.TCPAddr).Port

	// Port should not be available (it's in use)
	if IsPortAvailable(port) {
		t.Error("Port should not be available while listener is active")
	}

	listener.Close()
	time.Sleep(50 * time.Millisecond)

	// Port should now be available
	if !IsPortAvailable(port) {
		t.Error("Port should be available after closing listener")
	}
}

func TestGetFreePort(t *testing.T) {
	port, err := GetFreePort()
	if err != nil {
		t.Fatalf("GetFreePort failed: %v", err)
	}

	if port <= 0 || port > 65535 {
		t.Errorf("Invalid port: %d", port)
	}

	// Port should be available
	if !IsPortAvailable(port) {
		t.Error("GetFreePort returned unavailable port")
	}
}

// =============================================================================
// Bandwidth Limiter Tests
// =============================================================================

func TestBandwidthLimiter(t *testing.T) {
	// 1 KB/s limiter
	limiter := NewBandwidthLimiter(1024)

	// Send 512 bytes (should be fast)
	start := time.Now()
	limiter.Wait(512)
	elapsed := time.Since(start)

	if elapsed > 100*time.Millisecond {
		t.Errorf("Small transfer took too long: %v", elapsed)
	}

	// Send 2048 bytes (should take ~2 seconds at 1KB/s)
	start = time.Now()
	limiter.Wait(2048)
	elapsed = time.Since(start)

	// Should take at least 1 second (we already used 512 bytes)
	if elapsed < 500*time.Millisecond {
		t.Errorf("Large transfer too fast: %v", elapsed)
	}
}

func TestBandwidthLimiter_Concurrent(t *testing.T) {
	limiter := NewBandwidthLimiter(1024)

	var wg sync.WaitGroup
	start := time.Now()

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			limiter.Wait(512)
		}()
	}

	wg.Wait()
	elapsed := time.Since(start)

	// 5 * 512 bytes = 2560 bytes at 1KB/s should take ~2.5 seconds
	// Allow some tolerance
	if elapsed < time.Second {
		t.Errorf("Concurrent limiting too fast: %v", elapsed)
	}
}

// =============================================================================
// Network Statistics Tests
// =============================================================================

func TestNetworkStats_Record(t *testing.T) {
	stats := NewNetworkStats()

	stats.RecordSent(1024, 10)
	stats.RecordReceived(2048, 20)

	bytesSent, bytesRecv, packetsSent, packetsRecv := stats.GetStats()

	if bytesSent != 1024 {
		t.Errorf("BytesSent: got %d, want 1024", bytesSent)
	}

	if bytesRecv != 2048 {
		t.Errorf("BytesReceived: got %d, want 2048", bytesRecv)
	}

	if packetsSent != 10 {
		t.Errorf("PacketsSent: got %d, want 10", packetsSent)
	}

	if packetsRecv != 20 {
		t.Errorf("PacketsReceived: got %d, want 20", packetsRecv)
	}
}

func TestNetworkStats_Concurrent(t *testing.T) {
	stats := NewNetworkStats()

	var wg sync.WaitGroup
	iterations := 1000

	// Concurrent sends
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				stats.RecordSent(100, 1)
			}
		}()
	}

	// Concurrent receives
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				stats.RecordReceived(200, 2)
			}
		}()
	}

	wg.Wait()

	bytesSent, bytesRecv, packetsSent, packetsRecv := stats.GetStats()

	expectedBytesSent := int64(10 * iterations * 100)
	expectedBytesRecv := int64(10 * iterations * 200)
	expectedPacketsSent := int64(10 * iterations * 1)
	expectedPacketsRecv := int64(10 * iterations * 2)

	if bytesSent != expectedBytesSent {
		t.Errorf("BytesSent: got %d, want %d", bytesSent, expectedBytesSent)
	}

	if bytesRecv != expectedBytesRecv {
		t.Errorf("BytesReceived: got %d, want %d", bytesRecv, expectedBytesRecv)
	}

	if packetsSent != expectedPacketsSent {
		t.Errorf("PacketsSent: got %d, want %d", packetsSent, expectedPacketsSent)
	}

	if packetsRecv != expectedPacketsRecv {
		t.Errorf("PacketsReceived: got %d, want %d", packetsRecv, expectedPacketsRecv)
	}
}

func TestNetworkStats_Reset(t *testing.T) {
	stats := NewNetworkStats()

	stats.RecordSent(1024, 10)
	stats.RecordReceived(2048, 20)

	stats.Reset()

	bytesSent, bytesRecv, packetsSent, packetsRecv := stats.GetStats()

	if bytesSent != 0 || bytesRecv != 0 || packetsSent != 0 || packetsRecv != 0 {
		t.Error("Stats should be zero after Reset")
	}
}

// =============================================================================
// Retry Tests
// =============================================================================

func TestRetry_Success(t *testing.T) {
	ctx := context.Background()
	attempts := int32(0)

	err := Retry(ctx, 3, 10*time.Millisecond, func() error {
		count := atomic.AddInt32(&attempts, 1)
		if count < 2 {
			return fmt.Errorf("temporary error")
		}
		return nil
	})

	if err != nil {
		t.Fatalf("Retry failed: %v", err)
	}

	if atomic.LoadInt32(&attempts) != 2 {
		t.Errorf("Attempts: got %d, want 2", attempts)
	}
}

func TestRetry_MaxRetries(t *testing.T) {
	ctx := context.Background()
	attempts := int32(0)

	err := Retry(ctx, 3, 10*time.Millisecond, func() error {
		atomic.AddInt32(&attempts, 1)
		return fmt.Errorf("always fails")
	})

	if err == nil {
		t.Fatal("Retry should fail after max retries")
	}

	if atomic.LoadInt32(&attempts) != 3 {
		t.Errorf("Attempts: got %d, want 3", attempts)
	}
}

func TestRetry_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	attempts := int32(0)

	// Cancel after first attempt
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err := Retry(ctx, 10, 100*time.Millisecond, func() error {
		atomic.AddInt32(&attempts, 1)
		return fmt.Errorf("error")
	})

	if err != context.Canceled {
		t.Errorf("Expected context.Canceled, got %v", err)
	}

	// Should have stopped early
	if atomic.LoadInt32(&attempts) >= 10 {
		t.Errorf("Too many attempts after context cancellation: %d", attempts)
	}
}

func TestRetry_ExponentialBackoff(t *testing.T) {
	ctx := context.Background()
	attempts := int32(0)
	delays := make([]time.Duration, 0)
	lastTime := time.Now()

	err := Retry(ctx, 4, 50*time.Millisecond, func() error {
		count := atomic.AddInt32(&attempts, 1)
		now := time.Now()
		if count > 1 {
			delays = append(delays, now.Sub(lastTime))
		}
		lastTime = now
		return fmt.Errorf("error")
	})

	if err == nil {
		t.Fatal("Retry should fail")
	}

	// Check exponential backoff (each delay should be roughly 2x previous)
	// delays[0] ~50ms, delays[1] ~100ms, delays[2] ~200ms
	if len(delays) < 2 {
		t.Fatal("Not enough delays recorded")
	}

	for i := 1; i < len(delays); i++ {
		ratio := float64(delays[i]) / float64(delays[i-1])
		// Allow some tolerance (1.5x to 2.5x)
		if ratio < 1.5 || ratio > 2.5 {
			t.Errorf("Delay %d not exponential: %v vs %v (ratio: %.2f)", i, delays[i-1], delays[i], ratio)
		}
	}
}

// =============================================================================
// M9: Negative DNS Cache Tests
// =============================================================================

func TestNegativeDNSCache(t *testing.T) {
	resolver := NewDNSResolver(time.Second)

	// Lookup non-existent host should fail
	_, err := resolver.LookupIP("this-host-should-not-exist-99999.invalid")
	if err == nil {
		t.Fatal("Expected error for non-existent host")
	}

	// Second lookup should use negative cache (also fail, not panic)
	_, err2 := resolver.LookupIP("this-host-should-not-exist-99999.invalid")
	if err2 == nil {
		t.Error("Expected cached negative result to also error")
	}
}

// =============================================================================
// M10: LookupSRV Tests
// =============================================================================

func TestLookupSRVSignature(t *testing.T) {
	resolver := NewDNSResolver(time.Second)

	// LookupSRV should exist and be callable (may fail if no SRV record exists)
	records, err := resolver.LookupSRV("xmpp-client", "tcp", "jabber.org")
	// We don't assert success since this is a real DNS lookup that may fail in CI
	_ = records
	_ = err
}

// =============================================================================
// M11: WeightedRandom Load Balancer Tests
// =============================================================================

func TestWeightedRandomLoadBalancer(t *testing.T) {
	lb := NewLoadBalancer(WeightedRandom)

	// Add backends with different weights
	lb.AddBackend("heavy:8080", 10) // should be selected ~10/11 of the time
	lb.AddBackend("light:8080", 1)  // should be selected ~1/11 of the time

	seen := make(map[string]int)
	for i := 0; i < 110; i++ {
		b, err := lb.GetBackend("1.2.3.4")
		if err != nil {
			t.Fatalf("GetBackend failed: %v", err)
		}
		seen[b.Address]++
	}

	// heavy should win significantly more often
	if seen["heavy:8080"] <= seen["light:8080"] {
		t.Errorf("Weighted random not working: heavy=%d light=%d", seen["heavy:8080"], seen["light:8080"])
	}
}

// =============================================================================
// H15: WeightedRoundRobin Tests
// =============================================================================

func TestWeightedRoundRobin(t *testing.T) {
	lb := NewLoadBalancer(RoundRobin)

	lb.AddBackend("server1:8080", 3) // 3 slots
	lb.AddBackend("server2:8080", 1) // 1 slot

	seen := make(map[string]int)
	for i := 0; i < 40; i++ {
		b, err := lb.GetBackend("1.2.3.4")
		if err != nil {
			t.Fatalf("GetBackend failed: %v", err)
		}
		seen[b.Address]++
	}

	// server1 should be selected ~3x as often as server2
	if seen["server1:8080"] <= seen["server2:8080"] {
		t.Errorf("Weighted round-robin not working: server1=%d server2=%d", seen["server1:8080"], seen["server2:8080"])
	}
}

// =============================================================================
// L4: DNS IPv4/IPv6 Separation Tests
// =============================================================================

func TestDNSIPv4Lookup(t *testing.T) {
	resolver := NewDNSResolver(5 * time.Second)

	ips, err := resolver.LookupIPv4("localhost")
	if err != nil {
		t.Skipf("LookupIPv4 failed: %v", err)
	}
	for _, ip := range ips {
		if ip.To4() == nil {
			t.Errorf("LookupIPv4 returned non-IPv4 address: %v", ip)
		}
	}
}

func TestDNSIPv6Lookup(t *testing.T) {
	resolver := NewDNSResolver(5 * time.Second)

	// LookupIPv6 should return only IPv6 or empty list (localhost may not have IPv6 in all envs)
	_, err := resolver.LookupIPv6("localhost")
	if err != nil {
		t.Logf("LookupIPv6 returned error (acceptable in test env): %v", err)
	}
	// No assert on count since localhost may not have AAAA records
}

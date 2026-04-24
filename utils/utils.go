/*
Network Utilities
=================

Network utilities including DNS resolution, port scanning, load balancing, and connection helpers.

Applications:
- DNS lookups and resolution
- Port scanning and availability checks
- Load balancing algorithms
- Network diagnostics
- Connection utilities
*/

package utils

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"hash/fnv"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// DNS Resolution
// =============================================================================

// dnsCacheEntry holds cached DNS results with an expiry time
type dnsCacheEntry struct {
	ips      []net.IP // all IPs (backward compat)
	ipv4     []net.IP // L4: IPv4 only
	ipv6     []net.IP // L4: IPv6 only
	expiry   time.Time
	negative bool // M9: negative cache entry
}

// srvCacheEntry holds cached SRV records with an expiry time. (C5)
type srvCacheEntry struct {
	records []*net.SRV
	expiry  time.Time
}

// DNSResolver performs DNS lookups
type DNSResolver struct {
	timeout  time.Duration
	ttl      time.Duration
	negTTL   time.Duration // M9: TTL for negative cache entries
	cache    map[string]*dnsCacheEntry
	srvCache map[string]*srvCacheEntry // C5: SRV record cache
	mu       sync.RWMutex
	done     chan struct{}
}

// NewDNSResolver creates a DNS resolver with a default TTL of 60 seconds
func NewDNSResolver(timeout time.Duration) *DNSResolver {
	dr := &DNSResolver{
		timeout:  timeout,
		ttl:      60 * time.Second,
		negTTL:   10 * time.Second, // M9: 10s negative TTL
		cache:    make(map[string]*dnsCacheEntry),
		srvCache: make(map[string]*srvCacheEntry), // C5
		done:     make(chan struct{}),
	}
	dr.startEviction()
	return dr
}

// Close stops the background eviction goroutine. (B9/L2)
func (dr *DNSResolver) Close() {
	close(dr.done)
}

// startEviction starts a background goroutine that evicts expired entries every 60 seconds
func (dr *DNSResolver) startEviction() {
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				now := time.Now()
				dr.mu.Lock()
				for host, entry := range dr.cache {
					if now.After(entry.expiry) {
						delete(dr.cache, host)
					}
				}
				// C5: Also evict stale SRV cache entries.
				for key, entry := range dr.srvCache {
					if now.After(entry.expiry) {
						delete(dr.srvCache, key)
					}
				}
				dr.mu.Unlock()
			case <-dr.done:
				return
			}
		}
	}()
}

// LookupIP resolves hostname to IP addresses (A + AAAA)
func (dr *DNSResolver) LookupIP(hostname string) ([]net.IP, error) {
	// Check cache (with TTL check)
	dr.mu.RLock()
	if entry, ok := dr.cache[hostname]; ok && time.Now().Before(entry.expiry) {
		// M9: Return error for negative cache entry
		if entry.negative {
			dr.mu.RUnlock()
			return nil, errors.New("DNS lookup failed (cached)")
		}
		ips := entry.ips
		dr.mu.RUnlock()
		return ips, nil
	}
	dr.mu.RUnlock()

	// Resolve
	ctx, cancel := context.WithTimeout(context.Background(), dr.timeout)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", hostname)
	if err != nil {
		// M9: Cache negative result
		dr.mu.Lock()
		dr.cache[hostname] = &dnsCacheEntry{
			negative: true,
			expiry:   time.Now().Add(dr.negTTL),
		}
		dr.mu.Unlock()
		return nil, fmt.Errorf("DNS lookup failed: %w", err)
	}

	// L4: Separate IPv4 and IPv6
	var ipv4, ipv6 []net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			ipv4 = append(ipv4, ip)
		} else {
			ipv6 = append(ipv6, ip)
		}
	}

	// Cache result with TTL
	dr.mu.Lock()
	dr.cache[hostname] = &dnsCacheEntry{
		ips:    ips,
		ipv4:   ipv4,
		ipv6:   ipv6,
		expiry: time.Now().Add(dr.ttl),
	}
	dr.mu.Unlock()

	return ips, nil
}

// LookupIPv4 resolves hostname to IPv4 addresses only. (L4)
func (dr *DNSResolver) LookupIPv4(hostname string) ([]net.IP, error) {
	// Check cache
	dr.mu.RLock()
	if entry, ok := dr.cache[hostname]; ok && time.Now().Before(entry.expiry) {
		if entry.negative {
			dr.mu.RUnlock()
			return nil, errors.New("DNS lookup failed (cached)")
		}
		ipv4 := entry.ipv4
		dr.mu.RUnlock()
		return ipv4, nil
	}
	dr.mu.RUnlock()

	ips, err := dr.LookupIP(hostname)
	if err != nil {
		return nil, err
	}
	var result []net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			result = append(result, ip)
		}
	}
	return result, nil
}

// LookupIPv6 resolves hostname to IPv6 addresses only. (L4)
func (dr *DNSResolver) LookupIPv6(hostname string) ([]net.IP, error) {
	// Check cache
	dr.mu.RLock()
	if entry, ok := dr.cache[hostname]; ok && time.Now().Before(entry.expiry) {
		if entry.negative {
			dr.mu.RUnlock()
			return nil, errors.New("DNS lookup failed (cached)")
		}
		ipv6 := entry.ipv6
		dr.mu.RUnlock()
		return ipv6, nil
	}
	dr.mu.RUnlock()

	ips, err := dr.LookupIP(hostname)
	if err != nil {
		return nil, err
	}
	var result []net.IP
	for _, ip := range ips {
		if ip.To4() == nil {
			result = append(result, ip)
		}
	}
	return result, nil
}

// LookupSRV looks up SRV records for the given service. (M10, C5: TTL-cached)
func (dr *DNSResolver) LookupSRV(service, proto, name string) ([]*net.SRV, error) {
	key := service + "." + proto + "." + name

	// C5: Check the SRV cache first.
	dr.mu.RLock()
	if entry, ok := dr.srvCache[key]; ok && time.Now().Before(entry.expiry) {
		records := entry.records
		dr.mu.RUnlock()
		return records, nil
	}
	dr.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), dr.timeout)
	defer cancel()
	_, records, err := net.DefaultResolver.LookupSRV(ctx, service, proto, name)
	if err != nil {
		return nil, err
	}

	// C5: Cache the result.
	dr.mu.Lock()
	dr.srvCache[key] = &srvCacheEntry{records: records, expiry: time.Now().Add(dr.ttl)}
	dr.mu.Unlock()

	return records, nil
}

// LookupHost resolves IP to hostname
func (dr *DNSResolver) LookupHost(ip string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dr.timeout)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil {
		return nil, fmt.Errorf("reverse DNS lookup failed: %w", err)
	}

	return names, nil
}

// ClearCache clears DNS cache
func (dr *DNSResolver) ClearCache() {
	dr.mu.Lock()
	dr.cache = make(map[string]*dnsCacheEntry)
	dr.mu.Unlock()
}

// =============================================================================
// Port Scanner
// =============================================================================

// PortScanner scans for open ports
type PortScanner struct {
	Timeout     time.Duration
	Concurrency int
}

// NewPortScanner creates a port scanner
func NewPortScanner(timeout time.Duration, concurrency int) *PortScanner {
	if concurrency <= 0 {
		concurrency = 100
	}
	return &PortScanner{
		Timeout:     timeout,
		Concurrency: concurrency,
	}
}

// ScanPort checks if a port is open
func (ps *PortScanner) ScanPort(host string, port int) bool {
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", address, ps.Timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// ScanRange scans a range of ports
func (ps *PortScanner) ScanRange(host string, startPort, endPort int) []int {
	openPorts := make([]int, 0)
	var mu sync.Mutex

	sem := make(chan struct{}, ps.Concurrency)
	var wg sync.WaitGroup

	for port := startPort; port <= endPort; port++ {
		wg.Add(1)
		sem <- struct{}{}

		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			if ps.ScanPort(host, p) {
				mu.Lock()
				openPorts = append(openPorts, p)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	return openPorts
}

// =============================================================================
// Load Balancer
// =============================================================================

// LoadBalancerStrategy defines load balancing strategy
type LoadBalancerStrategy int

const (
	RoundRobin LoadBalancerStrategy = iota
	LeastConnections
	Random
	IPHash
	WeightedRandom // M11
)

// Backend represents a backend server
type Backend struct {
	Address     string
	Weight      int
	Active      bool
	Connections int64
	mu          sync.Mutex
}

// LoadBalancer distributes requests across backends
type LoadBalancer struct {
	Strategy LoadBalancerStrategy
	Backends []*Backend
	current  uint32
	mu       sync.RWMutex
}

// NewLoadBalancer creates a load balancer
func NewLoadBalancer(strategy LoadBalancerStrategy) *LoadBalancer {
	return &LoadBalancer{
		Strategy: strategy,
		Backends: make([]*Backend, 0),
	}
}

// AddBackend adds a backend server
func (lb *LoadBalancer) AddBackend(address string, weight int) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	lb.Backends = append(lb.Backends, &Backend{
		Address: address,
		Weight:  weight,
		Active:  true,
	})
}

// RemoveBackend removes a backend server
func (lb *LoadBalancer) RemoveBackend(address string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	for i, backend := range lb.Backends {
		if backend.Address == address {
			lb.Backends = append(lb.Backends[:i], lb.Backends[i+1:]...)
			return
		}
	}
}

// GetBackend selects a backend based on strategy
func (lb *LoadBalancer) GetBackend(clientIP string) (*Backend, error) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	if len(lb.Backends) == 0 {
		return nil, errors.New("no backends available")
	}

	// Filter active backends
	active := make([]*Backend, 0)
	for _, backend := range lb.Backends {
		if backend.Active {
			active = append(active, backend)
		}
	}

	if len(active) == 0 {
		return nil, errors.New("no active backends")
	}

	switch lb.Strategy {
	case RoundRobin:
		// H15: Weighted round-robin - expand ring by Weight
		ring := make([]*Backend, 0)
		for _, b := range active {
			w := b.Weight
			if w <= 0 {
				w = 1
			}
			for i := 0; i < w; i++ {
				ring = append(ring, b)
			}
		}
		idx := atomic.AddUint32(&lb.current, 1) % uint32(len(ring))
		return ring[idx], nil

	case LeastConnections:
		var selected *Backend
		minConns := int64(^uint64(0) >> 1) // Max int64

		for _, backend := range active {
			conns := atomic.LoadInt64(&backend.Connections)
			if conns < minConns {
				minConns = conns
				selected = backend
			}
		}
		return selected, nil

	case Random:
		idx := time.Now().UnixNano() % int64(len(active))
		return active[idx], nil

	case IPHash:
		h := fnv.New32a()
		h.Write([]byte(clientIP))
		idx := int(h.Sum32()) % len(active)
		return active[idx], nil

	case WeightedRandom:
		// M11: Cumulative weight selection with crypto/rand
		total := 0
		for _, b := range active {
			w := b.Weight
			if w <= 0 {
				w = 1
			}
			total += w
		}
		n, err := rand.Int(rand.Reader, big.NewInt(int64(total)))
		if err != nil {
			return active[0], nil
		}
		pick := int(n.Int64())
		for _, b := range active {
			w := b.Weight
			if w <= 0 {
				w = 1
			}
			pick -= w
			if pick < 0 {
				return b, nil
			}
		}
		return active[len(active)-1], nil

	default:
		return active[0], nil
	}
}

// MarkBackendDown marks a backend as inactive
func (lb *LoadBalancer) MarkBackendDown(address string) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	for _, backend := range lb.Backends {
		if backend.Address == address {
			backend.mu.Lock()
			backend.Active = false
			backend.mu.Unlock()
			return
		}
	}
}

// MarkBackendUp marks a backend as active
func (lb *LoadBalancer) MarkBackendUp(address string) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	for _, backend := range lb.Backends {
		if backend.Address == address {
			backend.mu.Lock()
			backend.Active = true
			backend.mu.Unlock()
			return
		}
	}
}

// IncrementConnections increments connection count for backend
func (b *Backend) IncrementConnections() {
	atomic.AddInt64(&b.Connections, 1)
}

// DecrementConnections decrements connection count for backend
func (b *Backend) DecrementConnections() {
	atomic.AddInt64(&b.Connections, -1)
}

// =============================================================================
// Connection Checker
// =============================================================================

// CheckConnection checks if a connection is alive
func CheckConnection(address string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// WaitForConnection waits for a connection to become available
func WaitForConnection(ctx context.Context, address string, checkInterval time.Duration) error {
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		if CheckConnection(address, time.Second) {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			continue
		}
	}
}

// =============================================================================
// Network Interface Info
// =============================================================================

// GetLocalIP gets local IP address
func GetLocalIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}

	return "", errors.New("no local IP found")
}

// GetAllLocalIPs returns all local IP addresses
func GetAllLocalIPs() ([]string, error) {
	ips := make([]string, 0)

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.To4() != nil {
					ips = append(ips, ipnet.IP.String())
				}
			}
		}
	}

	return ips, nil
}

// IsPortAvailable checks if a port is available for listening
func IsPortAvailable(port int) bool {
	address := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return false
	}
	listener.Close()
	return true
}

// GetFreePort finds an available port
func GetFreePort() (int, error) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	return addr.Port, nil
}

// =============================================================================
// Bandwidth Limiter
// =============================================================================

// BandwidthLimiter limits network bandwidth
type BandwidthLimiter struct {
	bytesPerSecond int64
	tokens         int64
	lastUpdate     time.Time
	mu             sync.Mutex
}

// NewBandwidthLimiter creates a bandwidth limiter
func NewBandwidthLimiter(bytesPerSecond int64) *BandwidthLimiter {
	return &BandwidthLimiter{
		bytesPerSecond: bytesPerSecond,
		tokens:         bytesPerSecond,
		lastUpdate:     time.Now(),
	}
}

// Wait waits until bytes can be sent, consuming tokens in chunks to support
// transfers larger than the per-second rate.
func (bl *BandwidthLimiter) Wait(bytes int64) {
	remaining := bytes
	for remaining > 0 {
		bl.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(bl.lastUpdate).Seconds()
		bl.tokens += int64(float64(bl.bytesPerSecond) * elapsed)
		if bl.tokens > bl.bytesPerSecond {
			bl.tokens = bl.bytesPerSecond
		}
		bl.lastUpdate = now

		if bl.tokens > 0 {
			consume := bl.tokens
			if consume > remaining {
				consume = remaining
			}
			bl.tokens -= consume
			remaining -= consume
		}
		bl.mu.Unlock()
		if remaining > 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// =============================================================================
// Network Statistics
// =============================================================================

// NetworkStats tracks network statistics
type NetworkStats struct {
	BytesSent     int64
	BytesReceived int64
	PacketsSent   int64
	PacketsReceived int64
	mu            sync.RWMutex
}

// NewNetworkStats creates network statistics tracker
func NewNetworkStats() *NetworkStats {
	return &NetworkStats{}
}

// RecordSent records sent data
func (ns *NetworkStats) RecordSent(bytes, packets int64) {
	atomic.AddInt64(&ns.BytesSent, bytes)
	atomic.AddInt64(&ns.PacketsSent, packets)
}

// RecordReceived records received data
func (ns *NetworkStats) RecordReceived(bytes, packets int64) {
	atomic.AddInt64(&ns.BytesReceived, bytes)
	atomic.AddInt64(&ns.PacketsReceived, packets)
}

// GetStats returns current statistics
func (ns *NetworkStats) GetStats() (bytesSent, bytesRecv, packetsSent, packetsRecv int64) {
	return atomic.LoadInt64(&ns.BytesSent),
		atomic.LoadInt64(&ns.BytesReceived),
		atomic.LoadInt64(&ns.PacketsSent),
		atomic.LoadInt64(&ns.PacketsReceived)
}

// Reset resets all statistics
func (ns *NetworkStats) Reset() {
	atomic.StoreInt64(&ns.BytesSent, 0)
	atomic.StoreInt64(&ns.BytesReceived, 0)
	atomic.StoreInt64(&ns.PacketsSent, 0)
	atomic.StoreInt64(&ns.PacketsReceived, 0)
}

// =============================================================================
// Retry Helper
// =============================================================================

// RetryFunc is a function that can be retried
type RetryFunc func() error

// Retry retries a function with exponential backoff
func Retry(ctx context.Context, maxRetries int, initialDelay time.Duration, fn RetryFunc) error {
	delay := initialDelay

	for attempt := 0; attempt < maxRetries; attempt++ {
		err := fn()
		if err == nil {
			return nil
		}

		if attempt < maxRetries-1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
				delay *= 2 // Exponential backoff
			}
		}
	}

	return fmt.Errorf("max retries (%d) exceeded", maxRetries)
}

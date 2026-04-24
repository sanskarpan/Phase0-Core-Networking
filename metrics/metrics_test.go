package metrics

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Each test group uses its own registry to avoid duplicate-registration panics. (O6)
var (
	onceHTTP   sync.Once
	sharedHTTP *HTTPMetrics
	regHTTP    = prometheus.NewRegistry()

	onceTCP   sync.Once
	sharedTCP *TCPMetrics
	regTCP    = prometheus.NewRegistry()
)

func getHTTPMetrics() *HTTPMetrics {
	onceHTTP.Do(func() { sharedHTTP = NewHTTPMetrics(regHTTP) })
	return sharedHTTP
}

func getTCPMetrics() *TCPMetrics {
	onceTCP.Do(func() { sharedTCP = NewTCPMetrics(regTCP) })
	return sharedTCP
}

// =============================================================================
// H14: HTTP Metrics Tests
// =============================================================================

func TestHTTPMetricsMiddleware(t *testing.T) {
	m := getHTTPMetrics()

	handler := m.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rec.Code)
	}
}

func TestHTTPMetricsMiddleware404(t *testing.T) {
	m := getHTTPMetrics()

	handler := m.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	req := httptest.NewRequest(http.MethodGet, "/missing", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", rec.Code)
	}
}

// =============================================================================
// H14: TCP Metrics Tests
// =============================================================================

func TestTCPMetricsConnections(t *testing.T) {
	m := getTCPMetrics()

	// Reset by decrementing any residual connections from prior tests
	for m.ActiveConnections() > 0 {
		m.DecrementConnections()
	}

	if m.ActiveConnections() != 0 {
		t.Errorf("Expected 0 active connections initially, got %d", m.ActiveConnections())
	}

	m.IncrementConnections()
	m.IncrementConnections()
	if m.ActiveConnections() != 2 {
		t.Errorf("Expected 2 active connections, got %d", m.ActiveConnections())
	}

	m.DecrementConnections()
	if m.ActiveConnections() != 1 {
		t.Errorf("Expected 1 active connection, got %d", m.ActiveConnections())
	}

	// Cleanup
	m.DecrementConnections()
}

func TestTCPMetricsBytesTracking(t *testing.T) {
	m := getTCPMetrics()

	// Just verify these don't panic
	m.RecordBytesReceived(1024)
	m.RecordBytesSent(2048)
}

// =============================================================================
// O1: RPC Metrics Tests
// =============================================================================

func TestRPCMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewRPCMetrics(reg)

	m.Record("echo", 10*time.Millisecond, nil)
	m.Record("fail", 5*time.Millisecond, fmt.Errorf("err"))
}

// =============================================================================
// O2: WebSocket Metrics Tests
// =============================================================================

func TestWebSocketMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewWebSocketMetrics(reg)

	m.ConnOpened()
	m.ConnOpened()
	m.MessageReceived(512)
	m.ConnClosed()
}

// =============================================================================
// O3: DNS Metrics Tests
// =============================================================================

func TestDNSMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewDNSMetrics(reg)

	m.CacheHit()
	m.CacheMiss()
	m.RecordLookup(2 * time.Millisecond)
}

// =============================================================================
// O4: Circuit Breaker Metrics Tests
// =============================================================================

func TestCircuitBreakerMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewCircuitBreakerMetrics(reg)

	m.SetState(0)
	m.SetState(2)
	m.RecordTrip()
}

// =============================================================================
// H14: ServeMetrics Test
// =============================================================================

func TestServeMetricsDoesNotPanic(t *testing.T) {
	// ServeMetrics starts a goroutine; just verify it doesn't panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ServeMetrics panicked: %v", r)
		}
	}()
	ServeMetrics(":0")
}

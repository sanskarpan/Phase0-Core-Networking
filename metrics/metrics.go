/*
Metrics
=======

Prometheus-based metrics for HTTP, TCP, RPC, WebSocket, DNS, and circuit-breaker.

Applications:
- HTTP request count and duration tracking
- TCP connection tracking
- RPC call count, latency, and error-rate tracking
- WebSocket active connection gauge and message counters
- DNS cache hit/miss rate and lookup latency
- Circuit breaker state and trip count
- Metrics exposition endpoint
*/

package metrics

import (
	"log/slog"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// =============================================================================
// HTTP Metrics (H14)
// =============================================================================

// HTTPMetrics records request count, duration, and status codes.
type HTTPMetrics struct {
	requestCount    *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
}

// NewHTTPMetrics creates a new HTTPMetrics instance with registered Prometheus collectors.
// O6: Accepts a prometheus.Registerer so callers can use their own registry to avoid
// duplicate-registration panics when multiple instances are created.
func NewHTTPMetrics(reg prometheus.Registerer) *HTTPMetrics {
	m := &HTTPMetrics{
		requestCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_total",
				Help: "Total number of HTTP requests",
			},
			[]string{"method", "path", "status"},
		),
		requestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_request_duration_seconds",
				Help:    "HTTP request duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "path"},
		),
	}
	reg.MustRegister(m.requestCount, m.requestDuration)
	return m
}

// statusRecorder wraps http.ResponseWriter to capture status code.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

// Middleware returns an http.Handler middleware that records metrics.
func (m *HTTPMetrics) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			duration := time.Since(start).Seconds()
			status := strconv.Itoa(rec.status)
			m.requestCount.WithLabelValues(r.Method, r.URL.Path, status).Inc()
			m.requestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(duration)
		})
	}
}

// =============================================================================
// TCP Metrics (H14)
// =============================================================================

// TCPMetrics records active connections and bytes transferred.
type TCPMetrics struct {
	activeConnections prometheus.Gauge
	bytesReceived     prometheus.Counter
	bytesSent         prometheus.Counter
	// Atomic counters for internal tracking
	activeConns int64
}

// NewTCPMetrics creates a new TCPMetrics instance.
// O6: Accepts a prometheus.Registerer.
func NewTCPMetrics(reg prometheus.Registerer) *TCPMetrics {
	m := &TCPMetrics{
		activeConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "tcp_active_connections",
			Help: "Number of active TCP connections",
		}),
		bytesReceived: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tcp_bytes_received_total",
			Help: "Total bytes received over TCP",
		}),
		bytesSent: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tcp_bytes_sent_total",
			Help: "Total bytes sent over TCP",
		}),
	}
	reg.MustRegister(m.activeConnections, m.bytesReceived, m.bytesSent)
	return m
}

// IncrementConnections records a new active connection.
func (m *TCPMetrics) IncrementConnections() {
	atomic.AddInt64(&m.activeConns, 1)
	m.activeConnections.Inc()
}

// DecrementConnections records a closed connection.
func (m *TCPMetrics) DecrementConnections() {
	atomic.AddInt64(&m.activeConns, -1)
	m.activeConnections.Dec()
}

// RecordBytesReceived records bytes received.
func (m *TCPMetrics) RecordBytesReceived(n int64) {
	m.bytesReceived.Add(float64(n))
}

// RecordBytesSent records bytes sent.
func (m *TCPMetrics) RecordBytesSent(n int64) {
	m.bytesSent.Add(float64(n))
}

// ActiveConnections returns the current active connection count.
func (m *TCPMetrics) ActiveConnections() int64 {
	return atomic.LoadInt64(&m.activeConns)
}

// =============================================================================
// RPC Metrics (O1)
// =============================================================================

// RPCMetrics tracks RPC call count, latency, and error rate per method.
type RPCMetrics struct {
	callCount   *prometheus.CounterVec
	callLatency *prometheus.HistogramVec
	errorRate   *prometheus.CounterVec
}

// NewRPCMetrics creates a new RPCMetrics instance. (O1)
func NewRPCMetrics(reg prometheus.Registerer) *RPCMetrics {
	m := &RPCMetrics{
		callCount: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "rpc_calls_total",
			Help: "Total number of RPC calls",
		}, []string{"method"}),
		callLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "rpc_call_duration_seconds",
			Help:    "RPC call latency",
			Buckets: prometheus.DefBuckets,
		}, []string{"method"}),
		errorRate: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "rpc_errors_total",
			Help: "Total number of RPC errors",
		}, []string{"method"}),
	}
	reg.MustRegister(m.callCount, m.callLatency, m.errorRate)
	return m
}

// Record records a completed RPC call.
func (m *RPCMetrics) Record(method string, duration time.Duration, err error) {
	m.callCount.WithLabelValues(method).Inc()
	m.callLatency.WithLabelValues(method).Observe(duration.Seconds())
	if err != nil {
		m.errorRate.WithLabelValues(method).Inc()
	}
}

// =============================================================================
// WebSocket Metrics (O2)
// =============================================================================

// WebSocketMetrics tracks active WebSocket connections, messages, and frame sizes.
type WebSocketMetrics struct {
	activeConns   prometheus.Gauge
	messagesTotal prometheus.Counter
	frameSizes    prometheus.Histogram
}

// NewWebSocketMetrics creates a new WebSocketMetrics instance. (O2)
func NewWebSocketMetrics(reg prometheus.Registerer) *WebSocketMetrics {
	m := &WebSocketMetrics{
		activeConns: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "websocket_active_connections",
			Help: "Number of active WebSocket connections",
		}),
		messagesTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "websocket_messages_total",
			Help: "Total number of WebSocket messages",
		}),
		frameSizes: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "websocket_frame_size_bytes",
			Help:    "WebSocket frame size distribution",
			Buckets: prometheus.ExponentialBuckets(64, 4, 8),
		}),
	}
	reg.MustRegister(m.activeConns, m.messagesTotal, m.frameSizes)
	return m
}

// ConnOpened records a new WebSocket connection.
func (m *WebSocketMetrics) ConnOpened() { m.activeConns.Inc() }

// ConnClosed records a closed WebSocket connection.
func (m *WebSocketMetrics) ConnClosed() { m.activeConns.Dec() }

// MessageReceived records a received WebSocket message and its size.
func (m *WebSocketMetrics) MessageReceived(size int) {
	m.messagesTotal.Inc()
	m.frameSizes.Observe(float64(size))
}

// =============================================================================
// DNS Metrics (O3)
// =============================================================================

// DNSMetrics tracks DNS cache hit/miss rate and lookup latency.
type DNSMetrics struct {
	cacheHits     prometheus.Counter
	cacheMisses   prometheus.Counter
	lookupLatency prometheus.Histogram
}

// NewDNSMetrics creates a new DNSMetrics instance. (O3)
func NewDNSMetrics(reg prometheus.Registerer) *DNSMetrics {
	m := &DNSMetrics{
		cacheHits: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "dns_cache_hits_total",
			Help: "Total DNS cache hits",
		}),
		cacheMisses: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "dns_cache_misses_total",
			Help: "Total DNS cache misses",
		}),
		lookupLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "dns_lookup_duration_seconds",
			Help:    "DNS lookup latency",
			Buckets: prometheus.DefBuckets,
		}),
	}
	reg.MustRegister(m.cacheHits, m.cacheMisses, m.lookupLatency)
	return m
}

// CacheHit records a DNS cache hit.
func (m *DNSMetrics) CacheHit() { m.cacheHits.Inc() }

// CacheMiss records a DNS cache miss.
func (m *DNSMetrics) CacheMiss() { m.cacheMisses.Inc() }

// RecordLookup records DNS lookup latency.
func (m *DNSMetrics) RecordLookup(d time.Duration) { m.lookupLatency.Observe(d.Seconds()) }

// =============================================================================
// Circuit Breaker Metrics (O4)
// =============================================================================

// CircuitBreakerMetrics tracks circuit breaker state and trip count.
type CircuitBreakerMetrics struct {
	state     prometheus.Gauge
	tripCount prometheus.Counter
}

// NewCircuitBreakerMetrics creates a new CircuitBreakerMetrics instance. (O4)
func NewCircuitBreakerMetrics(reg prometheus.Registerer) *CircuitBreakerMetrics {
	m := &CircuitBreakerMetrics{
		state: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "circuit_breaker_state",
			Help: "Circuit breaker state: 0=Closed, 1=HalfOpen, 2=Open",
		}),
		tripCount: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "circuit_breaker_trips_total",
			Help: "Total number of circuit breaker trips",
		}),
	}
	reg.MustRegister(m.state, m.tripCount)
	return m
}

// SetState updates the circuit breaker state gauge.
func (m *CircuitBreakerMetrics) SetState(state int) { m.state.Set(float64(state)) }

// RecordTrip records a circuit breaker trip.
func (m *CircuitBreakerMetrics) RecordTrip() { m.tripCount.Inc() }

// =============================================================================
// Metrics Server (H14)
// =============================================================================

// ServeMetrics starts a /metrics endpoint on addr using the default Prometheus registry.
// O5: Errors from ListenAndServe are now logged rather than silently swallowed.
func ServeMetrics(addr string) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	go func() {
		if err := http.ListenAndServe(addr, mux); err != nil && err != http.ErrServerClosed {
			slog.Error("metrics: serve failed", "addr", addr, "err", err)
		}
	}()
}

/*
HTTP/HTTPS Implementation
=========================

Comprehensive HTTP server and client implementations including middleware, routing, and utilities.

Applications:
- HTTP servers with middleware
- RESTful APIs
- HTTP clients with retry logic
- Request/Response handling
- File uploads/downloads
*/

package http

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof" // H17: side-effect import for pprof handlers
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/Phase0_Core/Networking/security"
)

// =============================================================================
// HTTP Server
// =============================================================================

// Handler is an HTTP request handler
type Handler func(w http.ResponseWriter, r *http.Request)

// Middleware wraps a handler with additional functionality
type Middleware func(Handler) Handler

// Server represents an HTTP server
type Server struct {
	Address    string
	TLSConfig  *tls.Config
	Timeout    time.Duration
	router     *Router
	server     *http.Server
	middleware []Middleware
	mu         sync.Mutex
}

// NewServer creates a new HTTP server
func NewServer(address string) *Server {
	return &Server{
		Address:    address,
		Timeout:    30 * time.Second,
		router:     NewRouter(),
		middleware: make([]Middleware, 0),
	}
}

// Use adds middleware to the server
func (s *Server) Use(middleware Middleware) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.middleware = append(s.middleware, middleware)
}

// Handle registers a handler for a path
func (s *Server) Handle(method, path string, handler Handler) {
	s.router.Handle(method, path, handler)
}

// GET registers a GET handler
func (s *Server) GET(path string, handler Handler) {
	s.Handle("GET", path, handler)
}

// POST registers a POST handler
func (s *Server) POST(path string, handler Handler) {
	s.Handle("POST", path, handler)
}

// PUT registers a PUT handler
func (s *Server) PUT(path string, handler Handler) {
	s.Handle("PUT", path, handler)
}

// DELETE registers a DELETE handler
func (s *Server) DELETE(path string, handler Handler) {
	s.Handle("DELETE", path, handler)
}

// buildHandler applies all registered middleware to the router and returns the resulting http.Handler. (B11)
func (s *Server) buildHandler() http.Handler {
	var h http.Handler = s.router
	for i := len(s.middleware) - 1; i >= 0; i-- {
		mw := s.middleware[i]
		inner := h
		h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mw(func(w http.ResponseWriter, r *http.Request) {
				inner.ServeHTTP(w, r)
			})(w, r)
		})
	}
	return h
}

// Start starts the HTTP server
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.Address)
	if err != nil {
		return err
	}

	s.mu.Lock()
	if s.server != nil {
		s.mu.Unlock()
		ln.Close()
		return errors.New("server already running")
	}

	// B11: Use buildHandler so all middleware is applied consistently.
	globalHandler := s.buildHandler()

	srv := &http.Server{
		Addr:         ln.Addr().String(),
		Handler:      globalHandler,
		ReadTimeout:  s.Timeout,
		WriteTimeout: s.Timeout,
		TLSConfig:    s.TLSConfig,
	}
	s.server = srv
	s.mu.Unlock()

	if s.TLSConfig != nil {
		return srv.Serve(tls.NewListener(ln, s.TLSConfig))
	}
	return srv.Serve(ln)
}

// Stop stops the HTTP server
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	if s.server == nil {
		s.mu.Unlock()
		return errors.New("server not running")
	}
	server := s.server
	s.server = nil
	s.mu.Unlock()

	return server.Shutdown(ctx)
}

// GetServer returns the underlying HTTP server
func (s *Server) GetServer() *http.Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.server
}

// =============================================================================
// Router
// =============================================================================

// paramKey is the context key for URL parameters
type paramKey struct{}

// GetParam retrieves a URL parameter from context (L1)
func GetParam(r *http.Request, name string) string {
	if params, ok := r.Context().Value(paramKey{}).(map[string]string); ok {
		return params[name]
	}
	return ""
}

// Router handles HTTP routing with support for :param and *wildcard paths (L1)
type Router struct {
	routes map[string]map[string]Handler // method -> path -> handler
	mu     sync.RWMutex
}

// NewRouter creates a new router
func NewRouter() *Router {
	return &Router{
		routes: make(map[string]map[string]Handler),
	}
}

// Handle registers a handler for method and path
func (r *Router) Handle(method, path string, handler Handler) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.routes[method] == nil {
		r.routes[method] = make(map[string]Handler)
	}
	r.routes[method][path] = handler
}

// matchPath attempts to match requestPath against a registered pattern.
// Returns matched params if successful.
func matchPath(pattern, requestPath string) (map[string]string, bool) {
	patParts := strings.Split(strings.Trim(pattern, "/"), "/")
	reqParts := strings.Split(strings.Trim(requestPath, "/"), "/")

	// Handle *wildcard: pattern ends with a wildcard segment
	if len(patParts) > 0 && strings.HasPrefix(patParts[len(patParts)-1], "*") {
		if len(reqParts) < len(patParts)-1 {
			return nil, false
		}
		params := make(map[string]string)
		for i := 0; i < len(patParts)-1; i++ {
			if strings.HasPrefix(patParts[i], ":") {
				params[patParts[i][1:]] = reqParts[i]
			} else if patParts[i] != reqParts[i] {
				return nil, false
			}
		}
		wildName := patParts[len(patParts)-1][1:]
		if wildName == "" {
			wildName = "*"
		}
		params[wildName] = strings.Join(reqParts[len(patParts)-1:], "/")
		return params, true
	}

	if len(patParts) != len(reqParts) {
		return nil, false
	}

	params := make(map[string]string)
	for i, pp := range patParts {
		if strings.HasPrefix(pp, ":") {
			params[pp[1:]] = reqParts[i]
		} else if pp != reqParts[i] {
			return nil, false
		}
	}
	return params, true
}

// ServeHTTP implements http.Handler
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Check for exact match first, then prefix match (routes ending in /)
	if handlers, ok := r.routes[req.Method]; ok {
		if handler, ok := handlers[req.URL.Path]; ok {
			handler(w, req)
			return
		}
		// Prefix match for trailing slash routes
		for pattern, handler := range handlers {
			if strings.HasSuffix(pattern, "/") && strings.HasPrefix(req.URL.Path, pattern) {
				handler(w, req)
				return
			}
		}
		// L1: Parameterized route matching
		for pattern, handler := range handlers {
			if strings.ContainsAny(pattern, ":*") {
				if params, ok := matchPath(pattern, req.URL.Path); ok {
					ctx := context.WithValue(req.Context(), paramKey{}, params)
					handler(w, req.WithContext(ctx))
					return
				}
			}
		}
	}

	// Check if path exists for any other method → 405
	for method, handlers := range r.routes {
		if method == req.Method {
			continue
		}
		if _, ok := handlers[req.URL.Path]; ok {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	http.NotFound(w, req)
}

// =============================================================================
// Common Middleware
// =============================================================================

// LoggingMiddleware logs requests
func LoggingMiddleware() Middleware {
	return func(next Handler) Handler {
		return func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			next(w, r)
			slog.Info("request", "method", r.Method, "path", r.URL.Path, "duration", time.Since(start))
		}
	}
}

// CORSMiddleware adds CORS headers, restricting to the provided list of allowed origins.
// Pass []string{"*"} to allow all origins.
func CORSMiddleware(allowedOrigins []string) Middleware {
	// Build lookup set for fast access
	originSet := make(map[string]bool, len(allowedOrigins))
	allowAll := false
	for _, o := range allowedOrigins {
		if o == "*" {
			allowAll = true
		}
		originSet[o] = true
	}

	return func(next Handler) Handler {
		return func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// If origin header is present, enforce the allowed list
			if origin != "" && !allowAll {
				if !originSet[origin] {
					http.Error(w, "Forbidden: origin not allowed", http.StatusForbidden)
					return
				}
			}

			// Set CORS headers
			if allowAll {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else if origin != "" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

			// L3: Handle OPTIONS preflight properly
			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID")
				w.Header().Set("Access-Control-Max-Age", "86400")
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next(w, r)
		}
	}
}

// AuthMiddleware checks for authorization token
func AuthMiddleware(validateToken func(string) bool) Middleware {
	return func(next Handler) Handler {
		return func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("Authorization")
			token = strings.TrimPrefix(token, "Bearer ")
			if token == "" || !validateToken(token) {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}
}

// rateLimitEntry tracks request count and reset time for a single client
type rateLimitEntry struct {
	count   int
	resetAt time.Time
	// LRU doubly-linked list pointers
	prev *rateLimitEntry
	next *rateLimitEntry
	key  string
}

// rateLimitLRU is a simple LRU cache for rate limiting entries
type rateLimitLRU struct {
	mu       sync.Mutex
	entries  map[string]*rateLimitEntry
	head     *rateLimitEntry // most recently used
	tail     *rateLimitEntry // least recently used
	maxSize  int
}

func newRateLimitLRU(maxSize int) *rateLimitLRU {
	return &rateLimitLRU{
		entries: make(map[string]*rateLimitEntry, maxSize),
		maxSize: maxSize,
	}
}

func (l *rateLimitLRU) get(key string) *rateLimitEntry {
	e, ok := l.entries[key]
	if !ok {
		return nil
	}
	l.moveToFront(e)
	return e
}

func (l *rateLimitLRU) put(key string, e *rateLimitEntry) {
	if old, ok := l.entries[key]; ok {
		l.remove(old)
	}
	l.entries[key] = e
	e.key = key
	l.addToFront(e)
	// Evict oldest if over capacity
	if len(l.entries) > l.maxSize {
		if l.tail != nil {
			l.evict(l.tail)
		}
	}
}

func (l *rateLimitLRU) addToFront(e *rateLimitEntry) {
	e.prev = nil
	e.next = l.head
	if l.head != nil {
		l.head.prev = e
	}
	l.head = e
	if l.tail == nil {
		l.tail = e
	}
}

func (l *rateLimitLRU) remove(e *rateLimitEntry) {
	if e.prev != nil {
		e.prev.next = e.next
	} else {
		l.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else {
		l.tail = e.prev
	}
	e.prev = nil
	e.next = nil
}

func (l *rateLimitLRU) moveToFront(e *rateLimitEntry) {
	l.remove(e)
	l.addToFront(e)
}

func (l *rateLimitLRU) evict(e *rateLimitEntry) {
	l.remove(e)
	delete(l.entries, e.key)
}

// RateLimitMiddleware limits requests per client with LRU eviction (max 10,000 entries)
// and a configurable window duration.
func RateLimitMiddleware(maxRequests int, window time.Duration) Middleware {
	const maxEntries = 10000
	lru := newRateLimitLRU(maxEntries)

	return func(next Handler) Handler {
		return func(w http.ResponseWriter, r *http.Request) {
			// B7: Use net.SplitHostPort to correctly handle IPv6 addresses like [::1]:1234
			clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
			if clientIP == "" {
				clientIP = r.RemoteAddr
			}

			lru.mu.Lock()
			info := lru.get(clientIP)
			now := time.Now()
			if info == nil || now.After(info.resetAt) {
				info = &rateLimitEntry{
					count:   0,
					resetAt: now.Add(window),
				}
				lru.put(clientIP, info)
			}

			if info.count >= maxRequests {
				lru.mu.Unlock()
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			info.count++
			lru.mu.Unlock()

			next(w, r)
		}
	}
}

// BodyLimit returns middleware that limits the request body to maxBytes. (P1)
func BodyLimit(maxBytes int64) Middleware {
	return func(next Handler) Handler {
		return func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next(w, r)
		}
	}
}

// HTTPMetricsMiddleware adapts a standard http.Handler middleware to the custom Middleware type. (P2)
// This bridges the metrics package's middleware type with the server's middleware chain.
func HTTPMetricsMiddleware(mw func(http.Handler) http.Handler) Middleware {
	return func(next Handler) Handler {
		return func(w http.ResponseWriter, r *http.Request) {
			mw(http.HandlerFunc(next)).ServeHTTP(w, r)
		}
	}
}

// RecoveryMiddleware recovers from panics and returns 500 (C1)
func RecoveryMiddleware() Middleware {
	return func(next Handler) Handler {
		return func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					slog.Error("http: panic in handler", "err", rec)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}()
			next(w, r)
		}
	}
}

// =============================================================================
// Gzip Middleware (H5)
// =============================================================================

var gzipWriterPool = sync.Pool{
	New: func() interface{} {
		w, _ := gzip.NewWriterLevel(io.Discard, gzip.DefaultCompression)
		return w
	},
}

type gzipResponseWriter struct {
	http.ResponseWriter
	gz *gzip.Writer
}

func (g *gzipResponseWriter) Write(b []byte) (int, error) {
	return g.gz.Write(b)
}

// GzipMiddleware compresses responses with gzip when client accepts it. (H5)
func GzipMiddleware() Middleware {
	return func(next Handler) Handler {
		return func(w http.ResponseWriter, r *http.Request) {
			if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				next(w, r)
				return
			}
			gz := gzipWriterPool.Get().(*gzip.Writer)
			defer gzipWriterPool.Put(gz)
			gz.Reset(w)
			defer gz.Close()
			w.Header().Set("Content-Encoding", "gzip")
			next(&gzipResponseWriter{w, gz}, r)
		}
	}
}

// =============================================================================
// Request ID Middleware (H6)
// =============================================================================

type requestIDKey struct{}

// RequestIDMiddleware generates a unique request ID per request. (H6)
func RequestIDMiddleware() Middleware {
	return func(next Handler) Handler {
		return func(w http.ResponseWriter, r *http.Request) {
			id := r.Header.Get("X-Request-ID")
			if id == "" {
				b := make([]byte, 16)
				rand.Read(b)
				id = hex.EncodeToString(b)
			}
			w.Header().Set("X-Request-ID", id)
			ctx := context.WithValue(r.Context(), requestIDKey{}, id)
			next(w, r.WithContext(ctx))
		}
	}
}

// GetRequestID retrieves the request ID from context. (H6)
func GetRequestID(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey{}).(string); ok {
		return v
	}
	return ""
}

// =============================================================================
// JWT Middleware (H7)
// =============================================================================

// JWTMiddleware validates Bearer JWT tokens. (H7)
func JWTMiddleware(j *security.JWT) Middleware {
	return func(next Handler) Handler {
		return func(w http.ResponseWriter, r *http.Request) {
			token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if token == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			if _, err := j.Verify(token); err != nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}
}

// =============================================================================
// API Key Middleware (H8)
// =============================================================================

// APIKeyMiddleware validates X-API-Key header. (H8)
func APIKeyMiddleware(m *security.APIKeyManager) Middleware {
	return func(next Handler) Handler {
		return func(w http.ResponseWriter, r *http.Request) {
			key := r.Header.Get("X-API-Key")
			if key == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			if _, err := m.Verify(key); err != nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}
}

// =============================================================================
// pprof endpoint (H17)
// =============================================================================

// RegisterPprof registers pprof debug handlers under /debug/pprof/. (H17)
func (s *Server) RegisterPprof() {
	s.Handle("GET", "/debug/pprof/", func(w http.ResponseWriter, r *http.Request) {
		http.DefaultServeMux.ServeHTTP(w, r)
	})
}

// =============================================================================
// Health endpoints (L7)
// =============================================================================

// RegisterHealthz registers /healthz and /readyz endpoints. (L7)
func (s *Server) RegisterHealthz() {
	s.GET("/healthz", func(w http.ResponseWriter, r *http.Request) {
		JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	startTime := time.Now()
	s.GET("/readyz", func(w http.ResponseWriter, r *http.Request) {
		JSON(w, http.StatusOK, map[string]string{
			"status": "ok",
			"uptime": time.Since(startTime).String(),
		})
	})
}

// =============================================================================
// HTTP/2 support (H4)
// =============================================================================

// StartH2C serves HTTP/2 over cleartext. (H4)
func (s *Server) StartH2C() error {
	ln, err := net.Listen("tcp", s.Address)
	if err != nil {
		return err
	}
	h2srv := &http2.Server{}
	s.mu.Lock()
	if s.server != nil {
		s.mu.Unlock()
		ln.Close()
		return errors.New("server already running")
	}
	// B11: Apply middleware via buildHandler so auth/rate-limit/etc. are not bypassed.
	srv := &http.Server{
		Addr:    ln.Addr().String(),
		Handler: h2c.NewHandler(s.buildHandler(), h2srv),
	}
	s.server = srv
	s.mu.Unlock()
	return srv.Serve(ln)
}

// StartTLS starts the server with TLS (enables HTTP/2 automatically). (H4)
func (s *Server) StartTLS(certFile, keyFile string) error {
	ln, err := net.Listen("tcp", s.Address)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.server != nil {
		s.mu.Unlock()
		ln.Close()
		return errors.New("server already running")
	}
	// B11: Apply middleware via buildHandler so auth/rate-limit/etc. are not bypassed.
	srv := &http.Server{
		Addr:    ln.Addr().String(),
		Handler: s.buildHandler(),
	}
	s.server = srv
	s.mu.Unlock()
	return srv.ServeTLS(ln, certFile, keyFile)
}

// =============================================================================
// HTTP Client
// =============================================================================

// Client represents an HTTP client
type Client struct {
	BaseURL      string
	Headers      map[string]string
	Timeout      time.Duration
	MaxRetries   int
	RetryDelay   time.Duration
	MaxRedirects int             // H16
	CookieJar    http.CookieJar // L2
	client       *http.Client
}

// NewClient creates a new HTTP client
func NewClient(baseURL string) *Client {
	c := &Client{
		BaseURL:      baseURL,
		Headers:      make(map[string]string),
		Timeout:      30 * time.Second,
		MaxRetries:   3,
		RetryDelay:   time.Second,
		MaxRedirects: 10, // H16
	}
	c.client = c.buildHTTPClient()
	return c
}

// buildHTTPClient constructs the underlying http.Client with current settings.
func (c *Client) buildHTTPClient() *http.Client {
	maxRedirects := c.MaxRedirects
	return &http.Client{
		Timeout: c.Timeout,
		Jar:     c.CookieJar, // L2
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// H16: Follow up to MaxRedirects
			if len(via) >= maxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// Get performs a GET request
func (c *Client) Get(ctx context.Context, path string) (*http.Response, error) {
	return c.doRequest(ctx, "GET", path, nil)
}

// Post performs a POST request
func (c *Client) Post(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	return c.doRequest(ctx, "POST", path, body)
}

// Put performs a PUT request
func (c *Client) Put(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	return c.doRequest(ctx, "PUT", path, body)
}

// Delete performs a DELETE request
func (c *Client) Delete(ctx context.Context, path string) (*http.Response, error) {
	return c.doRequest(ctx, "DELETE", path, nil)
}

func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	// L2: Update jar if changed
	if c.client.Jar != c.CookieJar {
		c.client = c.buildHTTPClient()
	}
	url := c.BaseURL + path

	// B3: Marshal body once before the retry loop, then create a fresh reader on each attempt.
	var jsonData []byte
	if body != nil {
		var merr error
		jsonData, merr = json.Marshal(body)
		if merr != nil {
			return nil, fmt.Errorf("failed to marshal body: %w", merr)
		}
	}

	var resp *http.Response
	var err error

	for attempt := 0; attempt <= c.MaxRetries; attempt++ {
		// B3: Re-create the reader each attempt so the body is never at EOF.
		var bodyReader io.Reader
		if jsonData != nil {
			bodyReader = bytes.NewReader(jsonData)
		}

		req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		// Add headers
		for key, value := range c.Headers {
			req.Header.Set(key, value)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err = c.client.Do(req)
		if err == nil && resp.StatusCode < 500 {
			return resp, nil
		}

		if attempt < c.MaxRetries {
			time.Sleep(c.RetryDelay)
		}
	}

	return resp, fmt.Errorf("request failed after %d retries: %w", c.MaxRetries, err)
}

// GetJSON performs GET and decodes JSON response
func (c *Client) GetJSON(ctx context.Context, path string, result interface{}) error {
	resp, err := c.Get(ctx, path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	return json.NewDecoder(resp.Body).Decode(result)
}

// PostJSON performs POST with JSON body and decodes JSON response
func (c *Client) PostJSON(ctx context.Context, path string, body interface{}, result interface{}) error {
	resp, err := c.Post(ctx, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	if result != nil {
		return json.NewDecoder(resp.Body).Decode(result)
	}

	return nil
}

// =============================================================================
// Response Helpers
// =============================================================================

// JSON writes a JSON response
func JSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// Error writes an error response
func Error(w http.ResponseWriter, status int, message string) {
	JSON(w, status, map[string]string{"error": message})
}

// Success writes a success response
func Success(w http.ResponseWriter, data interface{}) {
	JSON(w, http.StatusOK, map[string]interface{}{"success": true, "data": data})
}

// =============================================================================
// File Upload/Download
// =============================================================================

// UploadFile handles file uploads
func UploadFile(r *http.Request, fieldName string, maxSize int64) ([]byte, string, error) {
	if err := r.ParseMultipartForm(maxSize); err != nil {
		return nil, "", fmt.Errorf("failed to parse form: %w", err)
	}

	file, header, err := r.FormFile(fieldName)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get file: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read file: %w", err)
	}

	return data, header.Filename, nil
}

// DownloadFile sends a file download response
func DownloadFile(w http.ResponseWriter, filename string, data []byte) {
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.Write(data)
}

// =============================================================================
// WebSocket Upgrade Helper
// =============================================================================

// IsWebSocketUpgrade checks if request is WebSocket upgrade
func IsWebSocketUpgrade(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Upgrade")) == "websocket" &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// =============================================================================
// HTTP Connection Pool
// =============================================================================

// ConnectionPool manages HTTP client connections
type ConnectionPool struct {
	transport *http.Transport
	client    *http.Client
}

// NewConnectionPool creates an HTTP connection pool
func NewConnectionPool(maxIdleConns, maxIdleConnsPerHost int) *ConnectionPool {
	transport := &http.Transport{
		MaxIdleConns:        maxIdleConns,
		MaxIdleConnsPerHost: maxIdleConnsPerHost,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
	}

	return &ConnectionPool{
		transport: transport,
		client: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
	}
}

// GetClient returns the HTTP client
func (cp *ConnectionPool) GetClient() *http.Client {
	return cp.client
}

// Close closes all idle connections
func (cp *ConnectionPool) Close() {
	cp.transport.CloseIdleConnections()
}

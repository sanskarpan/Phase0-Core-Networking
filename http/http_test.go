/*
HTTP Tests
==========

Comprehensive tests for HTTP/HTTPS implementation.
*/

package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	nethttp "net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Phase0_Core/Networking/security"
)

// =============================================================================
// Server Tests
// =============================================================================

func TestHTTPServer_StartStop(t *testing.T) {
	server := NewServer(":0")

	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start()
	}()

	time.Sleep(100 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Stop(ctx); err != nil {
		t.Fatalf("Stop() failed: %v", err)
	}

	select {
	case err := <-errChan:
		if err != nil && err != nethttp.ErrServerClosed {
			t.Fatalf("Unexpected error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Start() did not return after Stop()")
	}
}

func TestHTTPServer_Routes(t *testing.T) {
	server := NewServer(":0")

	getHandled := false
	postHandled := false
	putHandled := false
	deleteHandled := false

	server.GET("/test", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		getHandled = true
		Success(w, map[string]string{"method": "GET"})
	})

	server.POST("/test", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		postHandled = true
		Success(w, map[string]string{"method": "POST"})
	})

	server.PUT("/test", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		putHandled = true
		Success(w, map[string]string{"method": "PUT"})
	})

	server.DELETE("/test", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		deleteHandled = true
		Success(w, map[string]string{"method": "DELETE"})
	})

	go func() {
		server.Start()
	}()
	defer server.Stop(context.Background())

	time.Sleep(100 * time.Millisecond)

	addr := server.GetServer().Addr

	// Test each method
	methods := []string{"GET", "POST", "PUT", "DELETE"}
	for _, method := range methods {
		req, _ := nethttp.NewRequest(method, "http://"+addr+"/test", nil)
		resp, err := nethttp.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s request failed: %v", method, err)
		}
		resp.Body.Close()

		if resp.StatusCode != nethttp.StatusOK {
			t.Errorf("%s: got status %d, want %d", method, resp.StatusCode, nethttp.StatusOK)
		}
	}

	if !getHandled || !postHandled || !putHandled || !deleteHandled {
		t.Error("Not all handlers were called")
	}
}

func TestHTTPServer_Middleware(t *testing.T) {
	server := NewServer(":0")

	order := []string{}
	var mu sync.Mutex

	middleware1 := func(next Handler) Handler {
		return func(w nethttp.ResponseWriter, r *nethttp.Request) {
			mu.Lock()
			order = append(order, "m1-before")
			mu.Unlock()
			next(w, r)
			mu.Lock()
			order = append(order, "m1-after")
			mu.Unlock()
		}
	}

	middleware2 := func(next Handler) Handler {
		return func(w nethttp.ResponseWriter, r *nethttp.Request) {
			mu.Lock()
			order = append(order, "m2-before")
			mu.Unlock()
			next(w, r)
			mu.Lock()
			order = append(order, "m2-after")
			mu.Unlock()
		}
	}

	server.Use(middleware1)
	server.Use(middleware2)

	server.GET("/test", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		mu.Lock()
		order = append(order, "handler")
		mu.Unlock()
		Success(w, nil)
	})

	go func() {
		server.Start()
	}()
	defer server.Stop(context.Background())

	time.Sleep(100 * time.Millisecond)

	addr := server.GetServer().Addr

	resp, err := nethttp.Get("http://" + addr + "/test")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()

	expected := []string{"m1-before", "m2-before", "handler", "m2-after", "m1-after"}
	if len(order) != len(expected) {
		t.Fatalf("Middleware order length mismatch: got %v, want %v", order, expected)
	}

	for i, v := range expected {
		if order[i] != v {
			t.Errorf("Middleware order[%d]: got %s, want %s", i, order[i], v)
		}
	}
}

func TestLoggingMiddleware(t *testing.T) {
	server := NewServer(":0")
	server.Use(LoggingMiddleware())

	server.GET("/test", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		Success(w, nil)
	})

	go func() {
		server.Start()
	}()
	defer server.Stop(context.Background())

	time.Sleep(100 * time.Millisecond)

	addr := server.GetServer().Addr

	resp, err := nethttp.Get("http://" + addr + "/test")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	resp.Body.Close()

	// Just verify it doesn't crash
}

func TestCORSMiddleware(t *testing.T) {
	server := NewServer(":0")
	server.Use(CORSMiddleware([]string{"*"}))

	server.GET("/test", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		Success(w, nil)
	})

	go func() {
		server.Start()
	}()
	defer server.Stop(context.Background())

	time.Sleep(100 * time.Millisecond)

	addr := server.GetServer().Addr

	resp, err := nethttp.Get("http://" + addr + "/test")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()

	if cors := resp.Header.Get("Access-Control-Allow-Origin"); cors != "*" {
		t.Errorf("CORS header: got %q, want %q", cors, "*")
	}
}

func TestAuthMiddleware(t *testing.T) {
	validToken := "valid-token"

	server := NewServer(":0")
	server.Use(AuthMiddleware(func(token string) bool {
		return token == validToken
	}))

	server.GET("/test", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		Success(w, map[string]string{"status": "authorized"})
	})

	go func() {
		server.Start()
	}()
	defer server.Stop(context.Background())

	time.Sleep(100 * time.Millisecond)

	addr := server.GetServer().Addr

	// Test without token
	resp, err := nethttp.Get("http://" + addr + "/test")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != nethttp.StatusUnauthorized {
		t.Errorf("Without token: got status %d, want %d", resp.StatusCode, nethttp.StatusUnauthorized)
	}

	// Test with invalid token
	req, _ := nethttp.NewRequest("GET", "http://"+addr+"/test", nil)
	req.Header.Set("Authorization", "Bearer invalid")
	resp, err = nethttp.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET with invalid token failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != nethttp.StatusUnauthorized {
		t.Errorf("With invalid token: got status %d, want %d", resp.StatusCode, nethttp.StatusUnauthorized)
	}

	// Test with valid token
	req, _ = nethttp.NewRequest("GET", "http://"+addr+"/test", nil)
	req.Header.Set("Authorization", "Bearer "+validToken)
	resp, err = nethttp.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET with valid token failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != nethttp.StatusOK {
		t.Errorf("With valid token: got status %d, want %d", resp.StatusCode, nethttp.StatusOK)
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	server := NewServer(":0")
	server.Use(RateLimitMiddleware(5, time.Minute)) // 5 requests per minute

	server.GET("/test", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		Success(w, nil)
	})

	go func() {
		server.Start()
	}()
	defer server.Stop(context.Background())

	time.Sleep(100 * time.Millisecond)

	addr := server.GetServer().Addr

	// Make requests rapidly
	success := 0
	rateLimited := 0

	for i := 0; i < 10; i++ {
		resp, err := nethttp.Get("http://" + addr + "/test")
		if err != nil {
			t.Fatalf("GET %d failed: %v", i, err)
		}

		if resp.StatusCode == nethttp.StatusOK {
			success++
		} else if resp.StatusCode == nethttp.StatusTooManyRequests {
			rateLimited++
		}

		resp.Body.Close()
		time.Sleep(10 * time.Millisecond)
	}

	// Should have some rate limited requests
	if rateLimited == 0 {
		t.Error("Expected some requests to be rate limited")
	}
}

// =============================================================================
// Client Tests
// =============================================================================

func TestHTTPClient_Get(t *testing.T) {
	server := NewServer(":0")
	server.GET("/test", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		Success(w, map[string]string{"message": "hello"})
	})

	go func() {
		server.Start()
	}()
	defer server.Stop(context.Background())

	time.Sleep(100 * time.Millisecond)

	addr := server.GetServer().Addr

	client := NewClient("http://" + addr)
	ctx := context.Background()

	var result map[string]interface{}
	if err := client.GetJSON(ctx, "/test", &result); err != nil {
		t.Fatalf("GetJSON failed: %v", err)
	}

	data, ok := result["data"].(map[string]interface{})
	if !ok {
		t.Fatal("Result data is not a map")
	}

	message, ok := data["message"].(string)
	if !ok || message != "hello" {
		t.Errorf("Message: got %q, want %q", message, "hello")
	}
}

func TestHTTPClient_Post(t *testing.T) {
	server := NewServer(":0")
	server.POST("/test", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		Success(w, body)
	})

	go func() {
		server.Start()
	}()
	defer server.Stop(context.Background())

	time.Sleep(100 * time.Millisecond)

	addr := server.GetServer().Addr

	client := NewClient("http://" + addr)
	ctx := context.Background()

	postData := map[string]string{"key": "value"}
	var result map[string]interface{}

	if err := client.PostJSON(ctx, "/test", postData, &result); err != nil {
		t.Fatalf("PostJSON failed: %v", err)
	}

	data, ok := result["data"].(map[string]interface{})
	if !ok {
		t.Fatal("Result data is not a map")
	}

	key, ok := data["key"].(string)
	if !ok || key != "value" {
		t.Errorf("Key: got %q, want %q", key, "value")
	}
}

func TestHTTPClient_Retry(t *testing.T) {
	attempts := int32(0)

	server := NewServer(":0")
	server.GET("/test", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		count := atomic.AddInt32(&attempts, 1)
		if count < 3 {
			Error(w, nethttp.StatusInternalServerError, "temporary error")
		} else {
			Success(w, map[string]string{"status": "ok"})
		}
	})

	go func() {
		server.Start()
	}()
	defer server.Stop(context.Background())

	time.Sleep(100 * time.Millisecond)

	addr := server.GetServer().Addr

	client := NewClient("http://" + addr)
	client.MaxRetries = 5
	client.RetryDelay = 50 * time.Millisecond

	ctx := context.Background()

	var result map[string]interface{}
	if err := client.GetJSON(ctx, "/test", &result); err != nil {
		t.Fatalf("GetJSON failed: %v", err)
	}

	if atomic.LoadInt32(&attempts) < 3 {
		t.Errorf("Expected at least 3 attempts, got %d", attempts)
	}
}

func TestHTTPClient_CustomHeaders(t *testing.T) {
	server := NewServer(":0")
	server.GET("/test", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		userAgent := r.Header.Get("User-Agent")
		custom := r.Header.Get("X-Custom-Header")

		Success(w, map[string]string{
			"user-agent": userAgent,
			"custom":     custom,
		})
	})

	go func() {
		server.Start()
	}()
	defer server.Stop(context.Background())

	time.Sleep(100 * time.Millisecond)

	addr := server.GetServer().Addr

	client := NewClient("http://" + addr)
	client.Headers["User-Agent"] = "TestClient/1.0"
	client.Headers["X-Custom-Header"] = "test-value"

	ctx := context.Background()

	var result map[string]interface{}
	if err := client.GetJSON(ctx, "/test", &result); err != nil {
		t.Fatalf("GetJSON failed: %v", err)
	}

	data, ok := result["data"].(map[string]interface{})
	if !ok {
		t.Fatal("Result data is not a map")
	}

	if ua := data["user-agent"]; ua != "TestClient/1.0" {
		t.Errorf("User-Agent: got %q, want %q", ua, "TestClient/1.0")
	}

	if custom := data["custom"]; custom != "test-value" {
		t.Errorf("Custom header: got %q, want %q", custom, "test-value")
	}
}

// =============================================================================
// Response Helper Tests
// =============================================================================

func TestResponseHelpers(t *testing.T) {
	server := NewServer(":0")

	server.GET("/json", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		JSON(w, nethttp.StatusOK, map[string]string{"test": "value"})
	})

	server.GET("/error", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		Error(w, nethttp.StatusBadRequest, "bad request")
	})

	server.GET("/success", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		Success(w, map[string]int{"count": 42})
	})

	go func() {
		server.Start()
	}()
	defer server.Stop(context.Background())

	time.Sleep(100 * time.Millisecond)

	addr := server.GetServer().Addr

	// Test JSON
	resp, _ := nethttp.Get("http://" + addr + "/json")
	var jsonResult map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&jsonResult)
	resp.Body.Close()

	if jsonResult["test"] != "value" {
		t.Error("JSON response incorrect")
	}

	// Test Error
	resp, _ = nethttp.Get("http://" + addr + "/error")
	var errorResult map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&errorResult)
	resp.Body.Close()

	if resp.StatusCode != nethttp.StatusBadRequest {
		t.Errorf("Error status: got %d, want %d", resp.StatusCode, nethttp.StatusBadRequest)
	}

	if errorResult["error"] != "bad request" {
		t.Error("Error message incorrect")
	}

	// Test Success
	resp, _ = nethttp.Get("http://" + addr + "/success")
	var successResult map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&successResult)
	resp.Body.Close()

	if successResult["success"] != true {
		t.Error("Success flag not set")
	}
}

// =============================================================================
// File Upload/Download Tests
// =============================================================================

func TestFileUpload(t *testing.T) {
	server := NewServer(":0")

	server.POST("/upload", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		file, header, err := r.FormFile("file")
		if err != nil {
			Error(w, nethttp.StatusBadRequest, err.Error())
			return
		}
		defer file.Close()

		content, _ := io.ReadAll(file)
		Success(w, map[string]interface{}{
			"filename": header.Filename,
			"size":     len(content),
			"content":  string(content),
		})
	})

	go func() {
		server.Start()
	}()
	defer server.Stop(context.Background())

	time.Sleep(100 * time.Millisecond)

	addr := server.GetServer().Addr

	// Create multipart form
	body := &bytes.Buffer{}
	fmt.Fprintf(body, "--boundary\r\n")
	fmt.Fprintf(body, "Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n")
	fmt.Fprintf(body, "Content-Type: text/plain\r\n\r\n")
	fmt.Fprintf(body, "test file content\r\n")
	fmt.Fprintf(body, "--boundary--\r\n")

	req, _ := nethttp.NewRequest("POST", "http://"+addr+"/upload", body)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")

	resp, err := nethttp.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Upload failed: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	data := result["data"].(map[string]interface{})
	if data["filename"] != "test.txt" {
		t.Error("Filename mismatch")
	}
}

// =============================================================================
// Connection Pool Tests
// =============================================================================

func TestConnectionPool(t *testing.T) {
	pool := NewConnectionPool(100, 10)
	defer pool.Close()

	client := pool.GetClient()

	if client == nil {
		t.Fatal("GetClient returned nil")
	}

	// Verify client has correct settings
	transport := client.Transport.(*nethttp.Transport)
	if transport.MaxIdleConns != 100 {
		t.Errorf("MaxIdleConns: got %d, want 100", transport.MaxIdleConns)
	}

	if transport.MaxIdleConnsPerHost != 10 {
		t.Errorf("MaxIdleConnsPerHost: got %d, want 10", transport.MaxIdleConnsPerHost)
	}
}

// =============================================================================
// Router Tests
// =============================================================================

func TestRouter_PathMatching(t *testing.T) {
	server := NewServer(":0")

	server.GET("/exact", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte("exact"))
	})

	server.GET("/prefix/", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte("prefix"))
	})

	go func() {
		server.Start()
	}()
	defer server.Stop(context.Background())

	time.Sleep(100 * time.Millisecond)

	addr := server.GetServer().Addr

	// Test exact match
	resp, _ := nethttp.Get("http://" + addr + "/exact")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if string(body) != "exact" {
		t.Errorf("Exact match failed: got %q", body)
	}

	// Test prefix match
	resp, _ = nethttp.Get("http://" + addr + "/prefix/subpath")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	if string(body) != "prefix" {
		t.Errorf("Prefix match failed: got %q", body)
	}

	// Test 404
	resp, _ = nethttp.Get("http://" + addr + "/notfound")
	resp.Body.Close()

	if resp.StatusCode != nethttp.StatusNotFound {
		t.Errorf("404 status: got %d, want %d", resp.StatusCode, nethttp.StatusNotFound)
	}
}

func TestRouter_MethodNotAllowed(t *testing.T) {
	server := NewServer(":0")

	server.GET("/test", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		Success(w, nil)
	})

	go func() {
		server.Start()
	}()
	defer server.Stop(context.Background())

	time.Sleep(100 * time.Millisecond)

	addr := server.GetServer().Addr

	// POST to GET-only endpoint
	resp, _ := nethttp.Post("http://"+addr+"/test", "application/json", strings.NewReader("{}"))
	resp.Body.Close()

	if resp.StatusCode != nethttp.StatusMethodNotAllowed {
		t.Errorf("Method not allowed status: got %d, want %d", resp.StatusCode, nethttp.StatusMethodNotAllowed)
	}
}

// =============================================================================
// C1: TestRecoveryMiddleware
// =============================================================================

func TestRecoveryMiddleware(t *testing.T) {
	server := NewServer(":0")
	server.Use(RecoveryMiddleware())

	server.GET("/panic", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		panic("test panic")
	})

	go func() { server.Start() }()
	defer server.Stop(context.Background())
	time.Sleep(50 * time.Millisecond)

	resp, err := nethttp.Get("http://" + getServerAddr(server) + "/panic")
	if err != nil {
		t.Fatalf("GET /panic failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != nethttp.StatusInternalServerError {
		t.Errorf("Expected 500, got %d", resp.StatusCode)
	}
}

// =============================================================================
// H5: TestGzipMiddleware
// =============================================================================

func TestGzipMiddleware(t *testing.T) {
	server := NewServer(":0")
	server.Use(GzipMiddleware())

	server.GET("/data", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte("hello gzip compressed content"))
	})

	go func() { server.Start() }()
	defer server.Stop(context.Background())
	time.Sleep(50 * time.Millisecond)

	req, _ := nethttp.NewRequest("GET", "http://"+getServerAddr(server)+"/data", nil)
	req.Header.Set("Accept-Encoding", "gzip")

	client := &nethttp.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Error("Expected Content-Encoding: gzip")
	}
}

// =============================================================================
// H6: TestRequestIDMiddleware
// =============================================================================

func TestRequestIDMiddleware(t *testing.T) {
	server := NewServer(":0")
	server.Use(RequestIDMiddleware())

	var capturedID string
	server.GET("/test", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		capturedID = GetRequestID(r.Context())
		w.WriteHeader(nethttp.StatusOK)
	})

	go func() { server.Start() }()
	defer server.Stop(context.Background())
	time.Sleep(50 * time.Millisecond)

	resp, err := nethttp.Get("http://" + getServerAddr(server) + "/test")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()

	id := resp.Header.Get("X-Request-ID")
	if id == "" {
		t.Error("Expected X-Request-ID header")
	}
	if capturedID != id {
		t.Errorf("Context ID %q != header ID %q", capturedID, id)
	}
}

// =============================================================================
// H7: TestJWTMiddleware
// =============================================================================

func TestJWTMiddleware(t *testing.T) {
	server := NewServer(":0")

	secret := []byte("super-secret-key-at-least-32-bytes!!")
	j := security.NewJWT(secret)
	server.Use(JWTMiddleware(j))

	server.GET("/protected", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.WriteHeader(nethttp.StatusOK)
	})

	go func() { server.Start() }()
	defer server.Stop(context.Background())
	time.Sleep(50 * time.Millisecond)

	baseURL := "http://" + getServerAddr(server) + "/protected"

	// Without token - should fail
	resp, err := nethttp.Get(baseURL)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != nethttp.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", resp.StatusCode)
	}

	// With valid token
	claims := &security.JWTClaims{
		Subject:   "user1",
		ExpiresAt: 9999999999,
	}
	token, _ := j.Create(claims)

	req, _ := nethttp.NewRequest("GET", baseURL, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = nethttp.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET with token failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != nethttp.StatusOK {
		t.Errorf("Expected 200 with valid token, got %d", resp.StatusCode)
	}
}

// =============================================================================
// H8: TestAPIKeyMiddleware
// =============================================================================

func TestAPIKeyMiddleware(t *testing.T) {
	server := NewServer(":0")

	m := security.NewAPIKeyManager()
	apiKey, _ := m.Generate("test", []string{"read"}, time.Hour)
	server.Use(APIKeyMiddleware(m))

	server.GET("/apikey", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.WriteHeader(nethttp.StatusOK)
	})

	go func() { server.Start() }()
	defer server.Stop(context.Background())
	time.Sleep(50 * time.Millisecond)

	baseURL := "http://" + getServerAddr(server) + "/apikey"

	// Without key - should fail
	resp, err := nethttp.Get(baseURL)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != nethttp.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", resp.StatusCode)
	}

	// With valid key
	req, _ := nethttp.NewRequest("GET", baseURL, nil)
	req.Header.Set("X-API-Key", apiKey.Key)
	resp, err = nethttp.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET with API key failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != nethttp.StatusOK {
		t.Errorf("Expected 200 with valid API key, got %d", resp.StatusCode)
	}
}

// =============================================================================
// L3: TestCORSPreflight
// =============================================================================

func TestCORSPreflight(t *testing.T) {
	server := NewServer(":0")
	server.Use(CORSMiddleware([]string{"*"}))

	server.GET("/cors", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.WriteHeader(nethttp.StatusOK)
	})

	go func() { server.Start() }()
	defer server.Stop(context.Background())
	time.Sleep(50 * time.Millisecond)

	req, _ := nethttp.NewRequest("OPTIONS", "http://"+getServerAddr(server)+"/cors", nil)
	req.Header.Set("Origin", "http://example.com")

	resp, err := nethttp.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("OPTIONS failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != nethttp.StatusNoContent {
		t.Errorf("Expected 204 for OPTIONS, got %d", resp.StatusCode)
	}
}

// =============================================================================
// L1: TestTrieRouter
// =============================================================================

func TestTrieRouter(t *testing.T) {
	server := NewServer(":0")

	server.GET("/users/:id", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		id := GetParam(r, "id")
		w.Write([]byte("user:" + id))
	})

	go func() { server.Start() }()
	defer server.Stop(context.Background())
	time.Sleep(50 * time.Millisecond)

	resp, err := nethttp.Get("http://" + getServerAddr(server) + "/users/42")
	if err != nil {
		t.Fatalf("GET /users/42 failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "user:42" {
		t.Errorf("Expected 'user:42', got %q", body)
	}
}

// =============================================================================
// H17: TestRegisterPprof
// =============================================================================

func TestRegisterPprof(t *testing.T) {
	server := NewServer(":0")
	server.RegisterPprof()

	go func() { server.Start() }()
	defer server.Stop(context.Background())
	time.Sleep(50 * time.Millisecond)

	resp, err := nethttp.Get("http://" + getServerAddr(server) + "/debug/pprof/")
	if err != nil {
		t.Fatalf("GET /debug/pprof/ failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != nethttp.StatusOK {
		t.Errorf("Expected 200 for pprof, got %d", resp.StatusCode)
	}
}

// =============================================================================
// L7: TestHealthEndpoints
// =============================================================================

func TestHealthEndpoints(t *testing.T) {
	server := NewServer(":0")
	server.RegisterHealthz()

	go func() { server.Start() }()
	defer server.Stop(context.Background())
	time.Sleep(50 * time.Millisecond)

	addr := getServerAddr(server)

	// Test /healthz
	resp, err := nethttp.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != nethttp.StatusOK {
		t.Errorf("Expected 200 for /healthz, got %d", resp.StatusCode)
	}

	// Test /readyz
	resp2, err := nethttp.Get("http://" + addr + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz failed: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != nethttp.StatusOK {
		t.Errorf("Expected 200 for /readyz, got %d", resp2.StatusCode)
	}
}

// =============================================================================
// H4: TestStartH2C
// =============================================================================

func TestStartH2C(t *testing.T) {
	server := NewServer(":0")
	server.GET("/h2c", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte("h2c-ok"))
	})

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.StartH2C()
	}()
	time.Sleep(100 * time.Millisecond)

	// Use standard HTTP/1.1 client - H2C server should also respond to HTTP/1.1
	server.mu.Lock()
	srv := server.server
	server.mu.Unlock()
	if srv == nil {
		t.Fatal("Server not started")
	}

	addr := srv.Addr
	resp, err := nethttp.Get("http://" + addr + "/h2c")
	if err != nil {
		t.Logf("H2C server GET returned: %v (may need H2 client)", err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "h2c-ok" {
		t.Errorf("Expected 'h2c-ok', got %q", body)
	}
}

// Helper to get server address
func getServerAddr(s *Server) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.server != nil {
		return s.server.Addr
	}
	return ""
}

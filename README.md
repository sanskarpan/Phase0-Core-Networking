# Networking Module

Comprehensive networking implementation in Go including TCP, UDP, HTTP/HTTPS, WebSockets, RPC, Security, and network utilities.

## Modules Implemented

### 1. TCP Socket Programming (`tcp/tcp.go`)

**Server:**
- TCP Server with connection handling
- Echo server pattern
- Connection statistics tracking
- Graceful shutdown support

**Client:**
- TCP Client with timeout support
- Send/Receive operations
- Connection management

**Advanced Features:**
- Connection Pooling with configurable limits
- Message Framing (length-prefixed messages)
- Keep-Alive connections with heartbeat
- Request-Response pattern

**Example:**
```go
// TCP Server
server := tcp.NewServer(":8080", tcp.EchoServer())
server.Start()

// TCP Client
client := tcp.NewClient("localhost:8080", 5*time.Second)
client.Connect()
client.Send([]byte("Hello"))
```

### 2. UDP Socket Programming (`udp/udp.go`)

**Server:**
- UDP Server with packet handling
- Echo server pattern
- Statistics tracking

**Client:**
- UDP Client with send/receive
- SendReceive combined operation

**Advanced Features:**
- Multicast support (join/leave groups)
- Broadcast support
- Reliable UDP (simplified retry logic)

**Example:**
```go
// UDP Server
server := udp.NewServer(":9090", udp.EchoServer(server))
server.Start()

// UDP Client
client := udp.NewClient("localhost:9090", 5*time.Second)
client.Connect()
client.SendReceive(data, buffer)
```

### 3. HTTP/HTTPS (`http/http.go`)

**Server:**
- HTTP Server with routing
- Middleware support
- Built-in middleware:
  - Logging
  - CORS
  - Authentication
  - Rate limiting

**Client:**
- HTTP Client with retry logic
- JSON helpers (GetJSON, PostJSON)
- Custom headers support
- Exponential backoff

**Utilities:**
- Response helpers (JSON, Error, Success)
- File upload/download
- WebSocket upgrade detection
- Connection pooling

**Example:**
```go
// HTTP Server
server := http.NewServer(":8080")
server.Use(http.LoggingMiddleware())
server.GET("/api/users", getUsersHandler)
server.POST("/api/users", createUserHandler)
server.Start()

// HTTP Client
client := http.NewClient("http://localhost:8080")
var result map[string]interface{}
client.GetJSON(ctx, "/api/users", &result)
```

### 4. WebSocket (`websocket/websocket.go`)

**Features:**
- Full WebSocket protocol implementation
- Frame reading/writing
- Ping/Pong heartbeat
- Text and binary messages
- Server and client support

**Server:**
- WebSocket server with message handling
- Upgrade from HTTP
- Connection management

**Client:**
- WebSocket client
- Connect/Send/Receive operations

**Example:**
```go
// WebSocket Server
wsServer := websocket.NewServer(func(conn *websocket.Conn, msgType byte, data []byte) {
    conn.WriteMessage(msgType, data) // Echo
})

// WebSocket Client
client := websocket.NewClient("ws://localhost:8080/ws")
client.Connect(ctx)
client.Send([]byte("Hello"))
data, _ := client.Receive()
```

### 5. Network Utilities (`utils/utils.go`)

**DNS Resolution:**
- IP lookup with caching
- Reverse DNS lookup
- Timeout support

**Port Scanner:**
- Single port check
- Port range scanning
- Concurrent scanning

**Load Balancer:**
- Multiple strategies:
  - Round Robin
  - Least Connections
  - Random
  - IP Hash
- Backend health checking
- Connection counting

**Connection Utilities:**
- Connection availability checking
- Wait for connection
- Local IP detection
- Port availability checking
- Free port finder

**Bandwidth Limiter:**
- Token bucket based limiting
- Configurable rate

**Network Statistics:**
- Bytes/packets sent/received tracking
- Thread-safe counters
- Reset functionality

**Retry Helper:**
- Exponential backoff
- Context support
- Configurable attempts

### 6. RPC (Remote Procedure Call) (`rpc/rpc.go`, `rpc/discovery.go`)

**RPC Framework:**
- Unary RPC (single request/response)
- Server streaming
- Client streaming
- Bidirectional streaming
- Message framing with JSON encoding
- Request/response correlation

**Load Balancing:**
- Round-robin strategy
- Random selection
- Least connections
- Multiple backend support

**Service Discovery:**
- Service registration and deregistration
- Health checking (TCP, HTTP)
- Service instance management
- Automatic instance discovery
- Heartbeat mechanism
- Watch for service changes

**Example:**
```go
// Create server
server := rpc.NewServer(":50051")
server.Register("Echo", func(ctx context.Context, req []byte) ([]byte, error) {
    return req, nil
})
server.Start()

// Create client
client := rpc.NewClient("localhost:50051")
client.Connect()
response, err := client.Call(ctx, "Echo", []byte("Hello"))

// Service discovery
registry := rpc.NewServiceRegistry(30*time.Second, 2*time.Minute)
registry.Register(&rpc.ServiceInstance{
    Name:    "echo-service",
    Address: "localhost",
    Port:    50051,
})
```

### 7. Security (`security/`)

**Cryptography (`crypto.go`):**
- Symmetric encryption (AES-256-GCM)
- Asymmetric encryption (RSA with OAEP)
- Digital signatures (RSA-PSS)
- Password hashing (bcrypt)
- Key derivation (PBKDF2)
- HMAC generation and verification

**TLS/SSL (`tls.go`):**
- Self-signed certificate generation
- CA certificate creation
- Certificate signing
- TLS server configuration
- TLS client configuration
- Mutual TLS (mTLS) support
- Certificate verification
- Certificate information extraction

**Authentication & Authorization (`auth.go`):**
- Password hashing with bcrypt
- JWT (JSON Web Tokens)
- API key management with scopes
- RBAC (Role-Based Access Control)
- Session management
- OAuth 2.0 token generation

**Example:**
```go
// Symmetric encryption
cipher, _ := security.NewAESCipher(key)
ciphertext, _ := cipher.Encrypt(plaintext)
plaintext, _ := cipher.Decrypt(ciphertext)

// TLS configuration
certPEM, keyPEM, _ := security.GenerateSelfSignedCert(config)
tlsConfig, _ := security.NewTLSConfig(certPEM, keyPEM)
server := security.NewTLSServer(":443", tlsConfig)

// JWT authentication
jwt := security.NewJWT(secret)
token, _ := jwt.Create(&security.JWTClaims{
    Subject:   "user123",
    ExpiresAt: time.Now().Add(time.Hour).Unix(),
})
claims, _ := jwt.Verify(token)

// RBAC
rbac := security.NewRBAC()
rbac.AddRole("admin", []security.Permission{"read", "write", "delete"})
rbac.AddUser("user1", "john", []string{"admin"})
allowed := rbac.CheckPermission("user1", "delete")
```

## Usage Examples

See `examples/main.go` for comprehensive demonstrations of all features.

Run the examples:
```bash
cd examples
go run main.go
```

## Running Tests

Build the module:
```bash
go build ./...
```

Run all tests:
```bash
go test ./... -v
```

Run tests for a specific module:
```bash
go test ./tcp -v      # TCP tests
go test ./udp -v      # UDP tests
go test ./http -v     # HTTP tests
go test ./websocket -v # WebSocket tests
go test ./utils -v    # Utils tests
```

Run tests with coverage:
```bash
go test ./... -cover
```

The test suite includes:
- **TCP Tests** (~25 tests): Server/client, connection pool, framing, keep-alive, request-response
- **UDP Tests** (~15 tests): Server/client, multicast, broadcast, reliable UDP
- **HTTP Tests** (~20 tests): Server/client, routing, middleware, response helpers
- **WebSocket Tests** (~15 tests): Frame parsing, messages, ping/pong, server/client
- **Utils Tests** (~25 tests): DNS, port scanning, load balancing, bandwidth limiting, stats

## Architecture

### TCP Module
```
tcp/
├── Server          # TCP server with connection handling
├── Client          # TCP client
├── ConnectionPool  # Connection pool manager
├── FrameWriter/Reader # Message framing
├── KeepAliveConn   # Keep-alive wrapper
└── RequestResponseClient # Request-response pattern
```

### UDP Module
```
udp/
├── Server          # UDP server
├── Client          # UDP client
├── MulticastServer # Multicast group support
├── BroadcastClient # Broadcast support
└── ReliableUDP     # Simplified reliable UDP
```

### HTTP Module
```
http/
├── Server          # HTTP server
├── Router          # Path routing
├── Client          # HTTP client with retry
├── Middleware      # Logging, CORS, Auth, RateLimit
├── Response Helpers # JSON, Error, Success
└── ConnectionPool  # HTTP connection pool
```

### WebSocket Module
```
websocket/
├── Conn            # WebSocket connection
├── Frame           # Frame parsing/writing
├── Server          # WebSocket server
├── Client          # WebSocket client
└── Upgrader        # HTTP to WebSocket upgrade
```

### Utils Module
```
utils/
├── DNSResolver     # DNS lookup with cache
├── PortScanner     # Port scanning
├── LoadBalancer    # Load balancing strategies
├── BandwidthLimiter # Rate limiting
├── NetworkStats    # Statistics tracking
└── Retry           # Retry helper
```

### RPC Module
```
rpc/
├── Server               # RPC server
├── Client               # RPC client
├── LoadBalancedClient   # Load-balanced client
├── ServiceRegistry      # Service registration
├── DiscoveryClient      # Service discovery
├── Heartbeat            # Keep-alive mechanism
├── ServerStream         # Server-side streaming
└── ClientStream         # Client-side streaming
```

### Security Module
```
security/
├── AESCipher           # Symmetric encryption
├── RSACipher           # Asymmetric encryption
├── PasswordHasher      # Password hashing
├── JWT                 # JSON Web Tokens
├── APIKeyManager       # API key management
├── RBAC                # Role-based access control
├── SessionManager      # Session management
├── TLSConfig           # TLS configuration
├── TLSServer           # TLS server
└── TLSClient           # TLS client
```

## Performance Considerations

- **Connection Pooling**: Reuses TCP/HTTP connections to reduce overhead
- **Concurrent Processing**: Goroutines for handling multiple connections
- **Buffering**: Buffered channels and I/O for better throughput
- **Keep-Alive**: TCP keep-alive to maintain long-lived connections
- **Rate Limiting**: Protects servers from overload

## Best Practices

1. **Always set timeouts** to prevent indefinite blocking
2. **Use connection pools** for frequently accessed services
3. **Implement graceful shutdown** for servers
4. **Handle errors properly** with retries where appropriate
5. **Monitor statistics** for debugging and optimization
6. **Use middleware** for cross-cutting concerns
7. **Validate input** to prevent security issues

## Production Readiness

All modules include:
- Proper error handling
- Context support for cancellation
- Thread-safe implementations
- Resource cleanup with `defer`
- Statistics and monitoring
- Graceful shutdown support

## Real-World Applications

- **Microservices**: HTTP/gRPC communication
- **Real-time Chat**: WebSocket for bidirectional communication
- **Load Balancing**: Distribute traffic across servers
- **Service Discovery**: DNS-based service location
- **API Gateways**: HTTP routing and middleware
- **Monitoring Systems**: Statistics collection
- **File Transfer**: TCP/UDP data transmission

## Integration

Works with standard Go libraries:
- `net` package for low-level networking
- `net/http` for HTTP
- `context` for cancellation
- `sync` for concurrency
- `time` for timeouts


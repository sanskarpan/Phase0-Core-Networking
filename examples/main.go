/*
Networking Examples
===================

Comprehensive examples demonstrating all networking features.
*/

package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	nethttp "net/http"

	"github.com/Phase0_Core/Networking/http"
	"github.com/Phase0_Core/Networking/tcp"
	"github.com/Phase0_Core/Networking/udp"
	"github.com/Phase0_Core/Networking/utils"
	"github.com/Phase0_Core/Networking/websocket"
)

func main() {
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("Networking Module - Comprehensive Examples")
	fmt.Println(strings.Repeat("=", 70))

	// TCP Examples
	demoTCP()

	// UDP Examples
	demoUDP()

	// HTTP Examples
	demoHTTP()

	// WebSocket Examples
	demoWebSocket()

	// Network Utilities
	demoNetworkUtils()

	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("All demonstrations completed successfully!")
	fmt.Println(strings.Repeat("=", 70))
}

// =============================================================================
// TCP Demonstrations
// =============================================================================

func demoTCP() {
	fmt.Println("\n" + strings.Repeat("-", 70))
	fmt.Println("TCP SOCKET PROGRAMMING")
	fmt.Println(strings.Repeat("-", 70))

	// 1. Simple TCP Echo Server
	fmt.Println("\n1. TCP Echo Server:")
	echoServer := tcp.NewServer(":8080", tcp.EchoServer())

	go func() {
		if err := echoServer.Start(); err != nil {
			fmt.Printf("  Server error: %v\n", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)
	fmt.Println("  TCP Echo Server started on :8080")

	// 2. TCP Client
	fmt.Println("\n2. TCP Client:")
	client := tcp.NewClient("localhost:8080", 5*time.Second)

	if err := client.Connect(); err != nil {
		fmt.Printf("  Connection failed: %v\n", err)
	} else {
		fmt.Println("  Connected to server")

		// Send data
		message := []byte("Hello, TCP Server!\n")
		if err := client.Send(message); err != nil {
			fmt.Printf("  Send failed: %v\n", err)
		} else {
			fmt.Println("  Sent: Hello, TCP Server!")
		}

		// Receive response
		buffer := make([]byte, 1024)
		n, err := client.Receive(buffer)
		if err != nil {
			fmt.Printf("  Receive failed: %v\n", err)
		} else {
			fmt.Printf("  Received: %s", string(buffer[:n]))
		}

		client.Close()
	}

	// 3. Connection Pool
	fmt.Println("\n3. TCP Connection Pool:")
	poolConfig := tcp.PoolConfig{
		MaxConnections: 10,
		MinConnections: 2,
		DialTimeout:    5 * time.Second,
		MaxIdleTime:    30 * time.Second,
	}

	pool, err := tcp.NewConnectionPool("localhost:8080", poolConfig)
	if err != nil {
		fmt.Printf("  Pool creation failed: %v\n", err)
	} else {
		fmt.Println("  Connection pool created")
		fmt.Printf("  Active connections: %d\n", pool.ActiveConnections())

		// Get connection from pool
		conn, err := pool.Get()
		if err != nil {
			fmt.Printf("  Get connection failed: %v\n", err)
		} else {
			fmt.Println("  Got connection from pool")
			pool.Put(conn)
			fmt.Println("  Returned connection to pool")
		}

		pool.Close()
	}

	// 4. Server Statistics
	fmt.Println("\n4. Server Statistics:")
	total, active, bytesRx, bytesTx := echoServer.GetStats()
	fmt.Printf("  Total connections: %d\n", total)
	fmt.Printf("  Active connections: %d\n", active)
	fmt.Printf("  Bytes received: %d\n", bytesRx)
	fmt.Printf("  Bytes sent: %d\n", bytesTx)

	// Cleanup
	echoServer.Stop()
	time.Sleep(100 * time.Millisecond)
}

// =============================================================================
// UDP Demonstrations
// =============================================================================

func demoUDP() {
	fmt.Println("\n" + strings.Repeat("-", 70))
	fmt.Println("UDP SOCKET PROGRAMMING")
	fmt.Println(strings.Repeat("-", 70))

	// 1. UDP Echo Server
	fmt.Println("\n1. UDP Echo Server:")
	udpServer := udp.NewServer(":9090", nil)
	udpServer.Handler = udp.EchoServer(udpServer)

	go func() {
		if err := udpServer.Start(); err != nil {
			fmt.Printf("  Server error: %v\n", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)
	fmt.Println("  UDP Echo Server started on :9090")

	// 2. UDP Client
	fmt.Println("\n2. UDP Client:")
	udpClient := udp.NewClient("localhost:9090", 5*time.Second)

	if err := udpClient.Connect(); err != nil {
		fmt.Printf("  Connection failed: %v\n", err)
	} else {
		fmt.Println("  Connected to server")

		// Send and receive
		message := []byte("Hello, UDP Server!")
		buffer := make([]byte, 1024)

		n, err := udpClient.SendReceive(message, buffer)
		if err != nil {
			fmt.Printf("  SendReceive failed: %v\n", err)
		} else {
			fmt.Printf("  Sent: Hello, UDP Server!\n")
			fmt.Printf("  Received: %s\n", string(buffer[:n]))
		}

		udpClient.Close()
	}

	// 3. Server Statistics
	fmt.Println("\n3. Server Statistics:")
	packetsRx, packetsTx, bytesRx, bytesTx := udpServer.GetStats()
	fmt.Printf("  Packets received: %d\n", packetsRx)
	fmt.Printf("  Packets sent: %d\n", packetsTx)
	fmt.Printf("  Bytes received: %d\n", bytesRx)
	fmt.Printf("  Bytes sent: %d\n", bytesTx)

	// Cleanup
	udpServer.Stop()
	time.Sleep(100 * time.Millisecond)
}

// =============================================================================
// HTTP Demonstrations
// =============================================================================

func demoHTTP() {
	fmt.Println("\n" + strings.Repeat("-", 70))
	fmt.Println("HTTP/HTTPS")
	fmt.Println(strings.Repeat("-", 70))

	// 1. HTTP Server with Middleware
	fmt.Println("\n1. HTTP Server with Middleware:")
	server := http.NewServer(":8081")

	// Add middleware
	server.Use(http.LoggingMiddleware())
	server.Use(http.CORSMiddleware([]string{"*"}))
	server.Use(http.RateLimitMiddleware(100, time.Minute))

	// Register handlers
	server.GET("/", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		http.Success(w, map[string]string{"message": "Welcome to the API"})
	})

	server.POST("/data", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		http.JSON(w, nethttp.StatusCreated, map[string]string{"status": "created"})
	})

	go func() {
		if err := server.Start(); err != nil && err != nethttp.ErrServerClosed {
			fmt.Printf("  Server error: %v\n", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)
	fmt.Println("  HTTP Server started on :8081")

	// 2. HTTP Client
	fmt.Println("\n2. HTTP Client with Retry:")
	client := http.NewClient("http://localhost:8081")
	client.MaxRetries = 3
	client.Headers["User-Agent"] = "Networking-Example/1.0"

	ctx := context.Background()

	// GET request
	var result map[string]interface{}
	if err := client.GetJSON(ctx, "/", &result); err != nil {
		fmt.Printf("  GET failed: %v\n", err)
	} else {
		fmt.Printf("  GET /: %v\n", result)
	}

	// POST request
	postData := map[string]string{"key": "value"}
	var postResult map[string]interface{}
	if err := client.PostJSON(ctx, "/data", postData, &postResult); err != nil {
		fmt.Printf("  POST failed: %v\n", err)
	} else {
		fmt.Printf("  POST /data: %v\n", postResult)
	}

	// 3. Connection Pool
	fmt.Println("\n3. HTTP Connection Pool:")
	connPool := http.NewConnectionPool(100, 10)
	httpClient := connPool.GetClient()
	fmt.Printf("  Connection pool created with client: %T\n", httpClient)

	// Cleanup
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Stop(ctx)
	connPool.Close()
	time.Sleep(100 * time.Millisecond)
}

// =============================================================================
// WebSocket Demonstrations
// =============================================================================

func demoWebSocket() {
	fmt.Println("\n" + strings.Repeat("-", 70))
	fmt.Println("WEBSOCKET")
	fmt.Println(strings.Repeat("-", 70))

	// 1. WebSocket Server
	fmt.Println("\n1. WebSocket Server:")
	wsServer := websocket.NewServer(func(conn *websocket.Conn, messageType byte, data []byte) {
		// Echo back the message
		conn.WriteMessage(messageType, data)
	})

	httpServer := &nethttp.Server{
		Addr:    ":8082",
		Handler: wsServer,
	}

	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != nethttp.ErrServerClosed {
			fmt.Printf("  Server error: %v\n", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)
	fmt.Println("  WebSocket Server started on :8082")

	// 2. WebSocket Client
	fmt.Println("\n2. WebSocket Client:")
	wsClient := websocket.NewClient("ws://localhost:8082/ws")

	ctx := context.Background()
	if err := wsClient.Connect(ctx); err != nil {
		fmt.Printf("  Connection failed: %v\n", err)
	} else {
		fmt.Println("  Connected to WebSocket server")

		// Send message
		message := []byte("Hello, WebSocket!")
		if err := wsClient.Send(message); err != nil {
			fmt.Printf("  Send failed: %v\n", err)
		} else {
			fmt.Println("  Sent: Hello, WebSocket!")
		}

		// Receive message (with timeout)
		go func() {
			data, err := wsClient.Receive()
			if err != nil {
				fmt.Printf("  Receive failed: %v\n", err)
			} else {
				fmt.Printf("  Received: %s\n", string(data))
			}
		}()

		time.Sleep(200 * time.Millisecond)
		wsClient.Close()
	}

	// Cleanup
	ctx2, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	httpServer.Shutdown(ctx2)
	time.Sleep(100 * time.Millisecond)
}

// =============================================================================
// Network Utilities Demonstrations
// =============================================================================

func demoNetworkUtils() {
	fmt.Println("\n" + strings.Repeat("-", 70))
	fmt.Println("NETWORK UTILITIES")
	fmt.Println(strings.Repeat("-", 70))

	// 1. DNS Resolution
	fmt.Println("\n1. DNS Resolution:")
	resolver := utils.NewDNSResolver(5 * time.Second)

	ips, err := resolver.LookupIP("localhost")
	if err != nil {
		fmt.Printf("  DNS lookup failed: %v\n", err)
	} else {
		fmt.Printf("  localhost resolves to: %v\n", ips)
	}

	// 2. Port Scanner
	fmt.Println("\n2. Port Scanner:")
	scanner := utils.NewPortScanner(time.Second, 10)

	// Check specific ports
	commonPorts := []int{80, 443, 8080, 8081, 8082, 9090}
	openPorts := make([]int, 0)

	for _, port := range commonPorts {
		if scanner.ScanPort("localhost", port) {
			openPorts = append(openPorts, port)
		}
	}

	fmt.Printf("  Open ports on localhost: %v\n", openPorts)

	// 3. Load Balancer
	fmt.Println("\n3. Load Balancer:")
	lb := utils.NewLoadBalancer(utils.RoundRobin)
	lb.AddBackend("server1:8080", 1)
	lb.AddBackend("server2:8080", 1)
	lb.AddBackend("server3:8080", 1)

	fmt.Println("  Load balancer created with 3 backends")

	for i := 0; i < 5; i++ {
		backend, err := lb.GetBackend("192.168.1.100")
		if err != nil {
			fmt.Printf("  Error: %v\n", err)
		} else {
			fmt.Printf("  Request %d -> %s\n", i+1, backend.Address)
		}
	}

	// 4. Network Interface Info
	fmt.Println("\n4. Network Interface Info:")
	localIP, err := utils.GetLocalIP()
	if err != nil {
		fmt.Printf("  Failed to get local IP: %v\n", err)
	} else {
		fmt.Printf("  Local IP: %s\n", localIP)
	}

	allIPs, err := utils.GetAllLocalIPs()
	if err != nil {
		fmt.Printf("  Failed to get all IPs: %v\n", err)
	} else {
		fmt.Printf("  All local IPs: %v\n", allIPs)
	}

	// 5. Port Availability
	fmt.Println("\n5. Port Availability:")
	testPort := 12345
	if utils.IsPortAvailable(testPort) {
		fmt.Printf("  Port %d is available\n", testPort)
	} else {
		fmt.Printf("  Port %d is in use\n", testPort)
	}

	freePort, err := utils.GetFreePort()
	if err != nil {
		fmt.Printf("  Failed to find free port: %v\n", err)
	} else {
		fmt.Printf("  Found free port: %d\n", freePort)
	}

	// 6. Bandwidth Limiter
	fmt.Println("\n6. Bandwidth Limiter:")
	limiter := utils.NewBandwidthLimiter(1024 * 1024) // 1 MB/s

	start := time.Now()
	dataSize := int64(1024 * 512) // 512 KB
	limiter.Wait(dataSize)
	elapsed := time.Since(start)

	fmt.Printf("  Transmitted %d bytes in %v\n", dataSize, elapsed)

	// 7. Network Statistics
	fmt.Println("\n7. Network Statistics:")
	stats := utils.NewNetworkStats()

	stats.RecordSent(1024, 10)
	stats.RecordReceived(2048, 15)

	bytesSent, bytesRecv, packetsSent, packetsRecv := stats.GetStats()
	fmt.Printf("  Bytes sent: %d, received: %d\n", bytesSent, bytesRecv)
	fmt.Printf("  Packets sent: %d, received: %d\n", packetsSent, packetsRecv)

	// 8. Retry Helper
	fmt.Println("\n8. Retry with Exponential Backoff:")
	ctx := context.Background()
	attempts := 0

	err = utils.Retry(ctx, 3, 10*time.Millisecond, func() error {
		attempts++
		if attempts < 2 {
			return fmt.Errorf("temporary error")
		}
		return nil
	})

	if err != nil {
		fmt.Printf("  Retry failed: %v\n", err)
	} else {
		fmt.Printf("  Succeeded after %d attempts\n", attempts)
	}
}

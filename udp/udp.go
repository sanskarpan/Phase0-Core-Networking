/*
UDP Socket Programming
======================

Comprehensive UDP implementations including servers, clients, multicast, and broadcast.

Applications:
- UDP server/client communication
- Multicast groups
- Broadcast messages
- Unreliable but fast communication
*/

package udp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// UDP Server
// =============================================================================

// PacketHandler processes incoming UDP packets
type PacketHandler func(addr *net.UDPAddr, data []byte)

// Server represents a UDP server
type Server struct {
	Address    string
	Handler    PacketHandler
	MaxWorkers int
	conn       *net.UDPConn
	done       chan struct{}
	wg         sync.WaitGroup
	mu         sync.Mutex
	active     bool
	workerSem  chan struct{}

	// Statistics
	PacketsReceived int64
	PacketsSent     int64
	BytesReceived   int64
	BytesSent       int64
}

// NewServer creates a new UDP server
func NewServer(address string, handler PacketHandler) *Server {
	return &Server{
		Address:    address,
		Handler:    handler,
		MaxWorkers: 100,
		done:       make(chan struct{}),
	}
}

// Start starts the UDP server
func (s *Server) Start() error {
	s.mu.Lock()
	if s.active {
		s.mu.Unlock()
		return errors.New("server already running")
	}

	addr, err := net.ResolveUDPAddr("udp", s.Address)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("invalid address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to start server: %w", err)
	}

	maxWorkers := s.MaxWorkers
	if maxWorkers <= 0 {
		maxWorkers = 100
	}
	s.workerSem = make(chan struct{}, maxWorkers)
	s.conn = conn
	s.active = true
	s.mu.Unlock()

	s.wg.Add(1)
	go s.receiveLoop()

	return nil
}

func (s *Server) receiveLoop() {
	defer s.wg.Done()

	buffer := make([]byte, 65535) // Max UDP packet size

	for {
		select {
		case <-s.done:
			return
		default:
			s.conn.SetReadDeadline(time.Now().Add(time.Second))
			n, addr, err := s.conn.ReadFromUDP(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				select {
				case <-s.done:
					return
				default:
					continue
				}
			}

			atomic.AddInt64(&s.PacketsReceived, 1)
			atomic.AddInt64(&s.BytesReceived, int64(n))

			// Copy data for handler
			data := make([]byte, n)
			copy(data, buffer[:n])

			// Use bounded worker pool to avoid unbounded goroutine creation
			select {
			case s.workerSem <- struct{}{}:
				go func() {
					defer func() { <-s.workerSem }()
					// C1: Panic recovery
					defer func() {
						if r := recover(); r != nil {
							slog.Error("udp: panic in handler", "err", r)
						}
					}()
					s.Handler(addr, data)
				}()
			default:
				// Worker pool exhausted: drop packet
			}
		}
	}
}

// SendTo sends data to specific address
func (s *Server) SendTo(addr *net.UDPAddr, data []byte) error {
	s.mu.Lock()
	if !s.active {
		s.mu.Unlock()
		return errors.New("server not running")
	}
	conn := s.conn
	s.mu.Unlock()

	n, err := conn.WriteToUDP(data, addr)
	if err == nil {
		atomic.AddInt64(&s.PacketsSent, 1)
		atomic.AddInt64(&s.BytesSent, int64(n))
	}
	return err
}

// Stop stops the UDP server
func (s *Server) Stop() error {
	s.mu.Lock()
	if !s.active {
		s.mu.Unlock()
		return errors.New("server not running")
	}

	close(s.done)
	s.conn.Close()
	s.active = false
	s.mu.Unlock()

	s.wg.Wait()
	return nil
}

// GetStats returns server statistics
func (s *Server) GetStats() (packetsRx, packetsTx, bytesRx, bytesTx int64) {
	return atomic.LoadInt64(&s.PacketsReceived),
		atomic.LoadInt64(&s.PacketsSent),
		atomic.LoadInt64(&s.BytesReceived),
		atomic.LoadInt64(&s.BytesSent)
}

// IsActive returns whether the server is currently active
func (s *Server) IsActive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

// GetConn returns the underlying UDP connection
func (s *Server) GetConn() *net.UDPConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn
}

// ListenIPv6 starts a UDP server bound to a udp6 address. (L9)
func (s *Server) ListenIPv6(addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp6", addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp6", udpAddr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.active {
		s.mu.Unlock()
		conn.Close()
		return errors.New("server already running")
	}
	maxWorkers := s.MaxWorkers
	if maxWorkers <= 0 {
		maxWorkers = 100
	}
	s.workerSem = make(chan struct{}, maxWorkers)
	s.conn = conn
	s.active = true
	s.mu.Unlock()
	s.wg.Add(1)
	go s.receiveLoop()
	return nil
}

// =============================================================================
// UDP Client
// =============================================================================

// Client represents a UDP client
type Client struct {
	RemoteAddress string
	LocalAddress  string
	Timeout       time.Duration
	conn          *net.UDPConn
	remoteAddr    *net.UDPAddr
	mu            sync.Mutex
}

// NewClient creates a new UDP client
func NewClient(remoteAddress string, timeout time.Duration) *Client {
	return &Client{
		RemoteAddress: remoteAddress,
		Timeout:       timeout,
	}
}

// Connect prepares the client for communication
func (c *Client) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		return errors.New("already connected")
	}

	remoteAddr, err := net.ResolveUDPAddr("udp", c.RemoteAddress)
	if err != nil {
		return fmt.Errorf("invalid remote address: %w", err)
	}
	c.remoteAddr = remoteAddr

	var localAddr *net.UDPAddr
	if c.LocalAddress != "" {
		localAddr, err = net.ResolveUDPAddr("udp", c.LocalAddress)
		if err != nil {
			return fmt.Errorf("invalid local address: %w", err)
		}
	}

	conn, err := net.DialUDP("udp", localAddr, remoteAddr)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}

	c.conn = conn
	return nil
}

// Send sends data to remote address
func (c *Client) Send(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return errors.New("not connected")
	}

	if c.Timeout > 0 {
		c.conn.SetWriteDeadline(time.Now().Add(c.Timeout))
	}

	_, err := c.conn.Write(data)
	return err
}

// Receive receives data from remote address
func (c *Client) Receive(buffer []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return 0, errors.New("not connected")
	}

	if c.Timeout > 0 {
		c.conn.SetReadDeadline(time.Now().Add(c.Timeout))
	}

	return c.conn.Read(buffer)
}

// SendReceive sends data and waits for response
func (c *Client) SendReceive(data []byte, respBuffer []byte) (int, error) {
	if err := c.Send(data); err != nil {
		return 0, err
	}
	return c.Receive(respBuffer)
}

// Close closes the connection
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil
	}

	err := c.conn.Close()
	c.conn = nil
	return err
}

// =============================================================================
// Multicast Support
// =============================================================================

// MulticastServer handles multicast groups
type MulticastServer struct {
	GroupAddress  string
	InterfaceName string
	conn          *net.UDPConn
	handler       PacketHandler
	done          chan struct{}
	wg            sync.WaitGroup
	mu            sync.Mutex
	active        bool
}

// NewMulticastServer creates a multicast server
func NewMulticastServer(groupAddress, interfaceName string, handler PacketHandler) *MulticastServer {
	return &MulticastServer{
		GroupAddress:  groupAddress,
		InterfaceName: interfaceName,
		handler:       handler,
		done:          make(chan struct{}),
	}
}

// Join joins the multicast group
func (ms *MulticastServer) Join() error {
	ms.mu.Lock()
	if ms.active {
		ms.mu.Unlock()
		return errors.New("already joined")
	}

	addr, err := net.ResolveUDPAddr("udp", ms.GroupAddress)
	if err != nil {
		ms.mu.Unlock()
		return fmt.Errorf("invalid group address: %w", err)
	}

	var iface *net.Interface
	if ms.InterfaceName != "" {
		iface, err = net.InterfaceByName(ms.InterfaceName)
		if err != nil {
			ms.mu.Unlock()
			return fmt.Errorf("invalid interface: %w", err)
		}
	}

	conn, err := net.ListenMulticastUDP("udp", iface, addr)
	if err != nil {
		ms.mu.Unlock()
		return fmt.Errorf("failed to join multicast group: %w", err)
	}

	ms.conn = conn
	ms.active = true
	ms.mu.Unlock()

	ms.wg.Add(1)
	go ms.receiveLoop()

	return nil
}

func (ms *MulticastServer) receiveLoop() {
	defer ms.wg.Done()

	buffer := make([]byte, 65535)

	for {
		select {
		case <-ms.done:
			return
		default:
			ms.conn.SetReadDeadline(time.Now().Add(time.Second))
			n, addr, err := ms.conn.ReadFromUDP(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				select {
				case <-ms.done:
					return
				default:
					continue
				}
			}

			data := make([]byte, n)
			copy(data, buffer[:n])

			go ms.handler(addr, data)
		}
	}
}

// Leave leaves the multicast group
func (ms *MulticastServer) Leave() error {
	ms.mu.Lock()
	if !ms.active {
		ms.mu.Unlock()
		return errors.New("not joined")
	}

	close(ms.done)
	ms.conn.Close()
	ms.active = false
	ms.mu.Unlock()

	ms.wg.Wait()
	return nil
}

// =============================================================================
// Broadcast Support
// =============================================================================

// BroadcastClient sends broadcast messages
type BroadcastClient struct {
	Port int
	conn *net.UDPConn
	mu   sync.Mutex
}

// NewBroadcastClient creates a broadcast client
func NewBroadcastClient(port int) *BroadcastClient {
	return &BroadcastClient{Port: port}
}

// Open opens the broadcast connection
func (bc *BroadcastClient) Open() error {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	if bc.conn != nil {
		return errors.New("already open")
	}

	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.IPv4bcast,
		Port: bc.Port,
	})
	if err != nil {
		return fmt.Errorf("failed to open broadcast: %w", err)
	}

	bc.conn = conn
	return nil
}

// Broadcast sends a broadcast message
func (bc *BroadcastClient) Broadcast(data []byte) error {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	if bc.conn == nil {
		return errors.New("not open")
	}

	_, err := bc.conn.Write(data)
	return err
}

// Close closes the broadcast connection
func (bc *BroadcastClient) Close() error {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	if bc.conn == nil {
		return nil
	}

	err := bc.conn.Close()
	bc.conn = nil
	return err
}

// =============================================================================
// Reliable UDP (Simple Implementation)
// =============================================================================

// ReliableUDP provides basic reliability over UDP
type ReliableUDP struct {
	conn        *net.UDPConn
	remoteAddr  *net.UDPAddr
	sequenceNum uint32
	ackTimeout  time.Duration
	maxRetries  int
	mu          sync.Mutex
	pendingAcks map[uint32]chan struct{}
	done        chan struct{} // B8/L1: stop readLoop goroutine
	// L5: receivedSeqs removed — it was allocated but never read or written.
}

// Packet represents a reliable UDP packet
type Packet struct {
	Sequence uint32
	Ack      bool
	Data     []byte
}

// NewReliableUDP creates a reliable UDP connection
func NewReliableUDP(conn *net.UDPConn, remoteAddr *net.UDPAddr, ackTimeout time.Duration, maxRetries int) *ReliableUDP {
	ru := &ReliableUDP{
		conn:        conn,
		remoteAddr:  remoteAddr,
		ackTimeout:  ackTimeout,
		maxRetries:  maxRetries,
		pendingAcks: make(map[uint32]chan struct{}),
		done:        make(chan struct{}), // B8/L1
	}
	go ru.readLoop()
	return ru
}

// Close closes the ReliableUDP connection and stops the readLoop goroutine. (B8/L1)
func (ru *ReliableUDP) Close() error {
	close(ru.done)
	return ru.conn.Close()
}

// readLoop reads incoming packets and signals pending ACK channels.
func (ru *ReliableUDP) readLoop() {
	buf := make([]byte, 65535)
	for {
		// Set a read deadline so we can check the done channel periodically.
		ru.conn.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err := ru.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ru.done:
				return
			default:
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}
		}
		// ACK format: [1 byte flag=1][4 bytes big-endian seq]
		if n >= 5 && buf[0] == 1 {
			seq := binary.BigEndian.Uint32(buf[1:5])
			ru.mu.Lock()
			ch, ok := ru.pendingAcks[seq]
			ru.mu.Unlock()
			if ok {
				select {
				case ch <- struct{}{}:
				default:
				}
			}
		}
	}
}

// SendReliable sends data with retry logic (simplified)
func (ru *ReliableUDP) SendReliable(ctx context.Context, data []byte) error {
	ru.mu.Lock()
	seq := atomic.AddUint32(&ru.sequenceNum, 1)
	ackChan := make(chan struct{}, 1)
	ru.pendingAcks[seq] = ackChan
	ru.mu.Unlock()

	defer func() {
		ru.mu.Lock()
		delete(ru.pendingAcks, seq)
		ru.mu.Unlock()
	}()

	// Build packet: [4-byte big-endian seq][data]
	packet := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(packet[:4], seq)
	copy(packet[4:], data)

	for attempt := 0; attempt < ru.maxRetries; attempt++ {
		if _, err := ru.conn.WriteToUDP(packet, ru.remoteAddr); err != nil {
			return err
		}

		// Wait for ACK
		select {
		case <-ackChan:
			return nil
		case <-time.After(ru.ackTimeout):
			continue
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return errors.New("max retries exceeded")
}

// =============================================================================
// UDP Echo Server (Common Pattern)
// =============================================================================

// EchoServer creates a UDP echo server handler
func EchoServer(server *Server) PacketHandler {
	return func(addr *net.UDPAddr, data []byte) {
		server.SendTo(addr, data)
	}
}

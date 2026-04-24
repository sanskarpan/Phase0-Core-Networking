/*
Service Discovery
=================

Service discovery implementation for microservices architecture.

Applications:
- Dynamic service registration
- Service health checking
- Load balancing across service instances
- Service metadata management
*/

package rpc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// =============================================================================
// Service Registry
// =============================================================================

// ServiceInstance represents a single service instance
type ServiceInstance struct {
	ID       string
	Name     string
	Address  string
	Port     int
	Metadata map[string]string
	Health   HealthStatus
	LastSeen time.Time
}

// HealthStatus represents service health
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusUnknown   HealthStatus = "unknown"
)

// ServiceRegistry maintains a registry of available services
type ServiceRegistry struct {
	services         map[string][]*ServiceInstance // service name -> instances
	mu               sync.RWMutex
	healthCheckInterval time.Duration
	timeout          time.Duration
	done             chan struct{}
	wg               sync.WaitGroup
}

// NewServiceRegistry creates a new service registry
func NewServiceRegistry(healthCheckInterval, timeout time.Duration) *ServiceRegistry {
	return &ServiceRegistry{
		services:         make(map[string][]*ServiceInstance),
		healthCheckInterval: healthCheckInterval,
		timeout:          timeout,
		done:             make(chan struct{}),
	}
}

// Register registers a service instance
func (sr *ServiceRegistry) Register(instance *ServiceInstance) error {
	if instance.Name == "" {
		return errors.New("service name is required")
	}
	if instance.Address == "" {
		return errors.New("service address is required")
	}

	sr.mu.Lock()
	defer sr.mu.Unlock()

	if instance.ID == "" {
		instance.ID = fmt.Sprintf("%s-%d-%d", instance.Name, instance.Port, time.Now().UnixNano())
	}

	instance.LastSeen = time.Now()
	instance.Health = HealthStatusHealthy

	sr.services[instance.Name] = append(sr.services[instance.Name], instance)

	return nil
}

// Deregister removes a service instance
func (sr *ServiceRegistry) Deregister(serviceName, instanceID string) error {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	instances, ok := sr.services[serviceName]
	if !ok {
		return fmt.Errorf("service not found: %s", serviceName)
	}

	for i, inst := range instances {
		if inst.ID == instanceID {
			sr.services[serviceName] = append(instances[:i], instances[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("instance not found: %s", instanceID)
}

// Discover returns all healthy instances of a service
func (sr *ServiceRegistry) Discover(serviceName string) ([]*ServiceInstance, error) {
	sr.mu.RLock()
	defer sr.mu.RUnlock()

	instances, ok := sr.services[serviceName]
	if !ok {
		return nil, fmt.Errorf("service not found: %s", serviceName)
	}

	healthy := make([]*ServiceInstance, 0)
	for _, inst := range instances {
		if inst.Health == HealthStatusHealthy {
			healthy = append(healthy, inst)
		}
	}

	if len(healthy) == 0 {
		return nil, errors.New("no healthy instances available")
	}

	return healthy, nil
}

// GetInstance returns a specific instance
func (sr *ServiceRegistry) GetInstance(serviceName, instanceID string) (*ServiceInstance, error) {
	sr.mu.RLock()
	defer sr.mu.RUnlock()

	instances, ok := sr.services[serviceName]
	if !ok {
		return nil, fmt.Errorf("service not found: %s", serviceName)
	}

	for _, inst := range instances {
		if inst.ID == instanceID {
			return inst, nil
		}
	}

	return nil, fmt.Errorf("instance not found: %s", instanceID)
}

// ListServices returns all registered service names
func (sr *ServiceRegistry) ListServices() []string {
	sr.mu.RLock()
	defer sr.mu.RUnlock()

	services := make([]string, 0, len(sr.services))
	for name := range sr.services {
		services = append(services, name)
	}

	return services
}

// UpdateHealth updates the health status of an instance
func (sr *ServiceRegistry) UpdateHealth(serviceName, instanceID string, health HealthStatus) error {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	instances, ok := sr.services[serviceName]
	if !ok {
		return fmt.Errorf("service not found: %s", serviceName)
	}

	for _, inst := range instances {
		if inst.ID == instanceID {
			inst.Health = health
			inst.LastSeen = time.Now()
			return nil
		}
	}

	return fmt.Errorf("instance not found: %s", instanceID)
}

// StartHealthCheck starts periodic health checking
func (sr *ServiceRegistry) StartHealthCheck(checker HealthChecker) {
	sr.wg.Add(1)
	go sr.healthCheckLoop(checker)
}

func (sr *ServiceRegistry) healthCheckLoop(checker HealthChecker) {
	defer sr.wg.Done()

	ticker := time.NewTicker(sr.healthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sr.performHealthChecks(checker)
		case <-sr.done:
			return
		}
	}
}

func (sr *ServiceRegistry) performHealthChecks(checker HealthChecker) {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	for serviceName, instances := range sr.services {
		for _, inst := range instances {
			// Check if instance is stale
			if time.Since(inst.LastSeen) > sr.timeout {
				inst.Health = HealthStatusUnhealthy
				continue
			}

			// Perform health check
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			healthy := checker.Check(ctx, inst)
			cancel()

			if healthy {
				inst.Health = HealthStatusHealthy
				inst.LastSeen = time.Now()
			} else {
				inst.Health = HealthStatusUnhealthy
			}
		}

		// Remove unhealthy instances that have been unhealthy for too long
		healthy := make([]*ServiceInstance, 0)
		for _, inst := range instances {
			if inst.Health == HealthStatusHealthy || time.Since(inst.LastSeen) < 5*sr.timeout {
				healthy = append(healthy, inst)
			}
		}
		sr.services[serviceName] = healthy
	}
}

// Stop stops the service registry
func (sr *ServiceRegistry) Stop() {
	close(sr.done)
	sr.wg.Wait()
}

// =============================================================================
// Health Checker
// =============================================================================

// HealthChecker interface for checking service health
type HealthChecker interface {
	Check(ctx context.Context, instance *ServiceInstance) bool
}

// TCPHealthChecker checks if a TCP port is open
type TCPHealthChecker struct{}

func (t *TCPHealthChecker) Check(ctx context.Context, instance *ServiceInstance) bool {
	address := fmt.Sprintf("%s:%d", instance.Address, instance.Port)

	conn, err := (&net.Dialer{
		Timeout: 2 * time.Second,
	}).DialContext(ctx, "tcp", address)

	if err != nil {
		return false
	}

	conn.Close()
	return true
}

// HTTPHealthChecker checks an HTTP endpoint
type HTTPHealthChecker struct {
	Path string
}

func (h *HTTPHealthChecker) Check(ctx context.Context, instance *ServiceInstance) bool {
	// C5: Real HTTP GET instead of TCP dial
	path := h.Path
	if path == "" {
		path = "/health"
	}
	url := fmt.Sprintf("http://%s:%d%s", instance.Address, instance.Port, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode < 500
}

// =============================================================================
// Service Discovery Client
// =============================================================================

// DiscoveryClient helps services discover and connect to other services
type DiscoveryClient struct {
	registry *ServiceRegistry
	mu       sync.RWMutex
}

// NewDiscoveryClient creates a new discovery client
func NewDiscoveryClient(registry *ServiceRegistry) *DiscoveryClient {
	return &DiscoveryClient{
		registry: registry,
	}
}

// GetService returns a client for the specified service
func (dc *DiscoveryClient) GetService(serviceName string, strategy string) (*LoadBalancedClient, error) {
	instances, err := dc.registry.Discover(serviceName)
	if err != nil {
		return nil, err
	}

	addresses := make([]string, len(instances))
	for i, inst := range instances {
		addresses[i] = fmt.Sprintf("%s:%d", inst.Address, inst.Port)
	}

	return NewLoadBalancedClient(addresses, strategy)
}

// Watch watches for service changes. The goroutine stops when ctx is cancelled. (L4)
func (dc *DiscoveryClient) Watch(ctx context.Context, serviceName string) (<-chan []*ServiceInstance, error) {
	ch := make(chan []*ServiceInstance, 1)

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		defer close(ch)

		var lastInstances []*ServiceInstance

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				instances, err := dc.registry.Discover(serviceName)
				if err != nil {
					continue
				}

				// Check if instances changed
				if !instancesEqual(instances, lastInstances) {
					select {
					case ch <- instances:
					case <-ctx.Done():
						return
					}
					lastInstances = instances
				}
			}
		}
	}()

	return ch, nil
}

func instancesEqual(a, b []*ServiceInstance) bool {
	if len(a) != len(b) {
		return false
	}

	idMap := make(map[string]bool)
	for _, inst := range a {
		idMap[inst.ID] = true
	}

	for _, inst := range b {
		if !idMap[inst.ID] {
			return false
		}
	}

	return true
}

// =============================================================================
// Heartbeat
// =============================================================================

// Heartbeat maintains service presence in registry
type Heartbeat struct {
	registry    *ServiceRegistry
	instance    *ServiceInstance
	interval    time.Duration
	done        chan struct{}
	wg          sync.WaitGroup
}

// NewHeartbeat creates a new heartbeat
func NewHeartbeat(registry *ServiceRegistry, instance *ServiceInstance, interval time.Duration) *Heartbeat {
	return &Heartbeat{
		registry: registry,
		instance: instance,
		interval: interval,
		done:     make(chan struct{}),
	}
}

// Start starts sending heartbeats
func (h *Heartbeat) Start() {
	h.wg.Add(1)
	go h.heartbeatLoop()
}

func (h *Heartbeat) heartbeatLoop() {
	defer h.wg.Done()

	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.registry.UpdateHealth(h.instance.Name, h.instance.ID, HealthStatusHealthy)
		case <-h.done:
			return
		}
	}
}

// Stop stops sending heartbeats
func (h *Heartbeat) Stop() {
	close(h.done)
	h.wg.Wait()
}

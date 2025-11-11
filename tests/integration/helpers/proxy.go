package helpers

import (
	"fmt"
	"net"
	"time"

	"github.com/souravcrl/attested-tls-proxy-cockroach/internal/config"
	"github.com/souravcrl/attested-tls-proxy-cockroach/pkg/backend"
)

// TestProxy manages a proxy instance for testing
type TestProxy struct {
	instance *backend.Proxy
	Port     int
	Config   *config.Config
	stopChan chan struct{}
}

// StartTestProxy starts a proxy instance for testing
func StartTestProxy(cfg *config.Config) (*TestProxy, error) {
	// If listen address has port 0, find an available port
	if cfg.Proxy.Listen == "127.0.0.1:0" || cfg.Proxy.Listen == "localhost:0" {
		port, err := findAvailablePort()
		if err != nil {
			return nil, fmt.Errorf("failed to find available port: %w", err)
		}
		cfg.Proxy.Listen = fmt.Sprintf("127.0.0.1:%d", port)
	}

	// Create proxy using the standard constructor
	proxy, err := backend.NewProxy(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create proxy: %w", err)
	}

	// Extract port from config
	_, portStr, err := net.SplitHostPort(cfg.Proxy.Listen)
	if err != nil {
		return nil, fmt.Errorf("failed to parse listen address: %w", err)
	}

	var port int
	fmt.Sscanf(portStr, "%d", &port)

	testProxy := &TestProxy{
		instance: proxy,
		Port:     port,
		Config:   cfg,
		stopChan: make(chan struct{}),
	}

	// Start proxy in background
	go func() {
		proxy.Start()
	}()

	// Wait for proxy to be ready
	time.Sleep(200 * time.Millisecond)

	return testProxy, nil
}

// Stop stops the proxy instance
func (p *TestProxy) Stop() error {
	if p.instance != nil {
		p.instance.Stop()
		p.instance.WaitForConnections()
	}

	if p.stopChan != nil {
		close(p.stopChan)
	}

	return nil
}

// GetAddr returns the proxy address
func (p *TestProxy) GetAddr() string {
	return fmt.Sprintf("localhost:%d", p.Port)
}

// WaitForProxy waits for the proxy to be ready
func WaitForProxy(proxy *TestProxy, timeout int) error {
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)

	for time.Now().Before(deadline) {
		// Try to connect
		conn, err := net.DialTimeout("tcp", proxy.GetAddr(), 1*time.Second)
		if err == nil {
			conn.Close()
			return nil
		}

		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("proxy did not become ready within %d seconds", timeout)
}
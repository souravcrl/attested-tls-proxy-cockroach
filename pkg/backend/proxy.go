package backend

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/souravcrl/attested-tls-proxy-cockroach/internal/config"
	"github.com/souravcrl/attested-tls-proxy-cockroach/internal/logger"
)

// Proxy represents the TLS proxy server
type Proxy struct {
	config      *config.Config
	listener    net.Listener
	pool        *ConnectionPool
	activeConns sync.WaitGroup
	shutdown    chan struct{}
	mu          sync.Mutex
	running     bool
}

// NewProxy creates a new proxy instance
func NewProxy(cfg *config.Config) (*Proxy, error) {
	// Create connection pool (max 100 connections)
	pool, err := NewConnectionPool(&cfg.Proxy.Backend, 100)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	return &Proxy{
		config:   cfg,
		pool:     pool,
		shutdown: make(chan struct{}),
	}, nil
}

// Start starts the proxy server
func (p *Proxy) Start() error {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return fmt.Errorf("proxy is already running")
	}
	p.running = true
	p.mu.Unlock()

	// Create listener
	listener, err := net.Listen("tcp", p.config.Proxy.Listen)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", p.config.Proxy.Listen, err)
	}
	p.listener = listener

	logger.Log.Info().
		Str("address", p.config.Proxy.Listen).
		Msg("Proxy started, waiting for connections")

	// Accept connections
	for {
		select {
		case <-p.shutdown:
			logger.Info("Proxy shutting down")
			return nil
		default:
			// Set accept timeout to allow checking shutdown signal
			if tcpListener, ok := listener.(*net.TCPListener); ok {
				tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
			}

			conn, err := listener.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue // Timeout, check shutdown signal
				}
				if !p.isRunning() {
					return nil // Shutting down
				}
				logger.Error("Failed to accept connection", err)
				continue
			}

			// Handle connection in goroutine
			p.activeConns.Add(1)
			go p.handleConnection(conn)
		}
	}
}

// Stop gracefully stops the proxy
func (p *Proxy) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running {
		return
	}

	logger.Info("Stopping proxy...")
	close(p.shutdown)
	p.running = false

	if p.listener != nil {
		p.listener.Close()
	}

	// Close connection pool
	p.pool.Close()
}

// WaitForConnections waits for all active connections to finish
func (p *Proxy) WaitForConnections() {
	p.activeConns.Wait()
	logger.Info("All connections closed")
}

// handleConnection handles a single client connection
func (p *Proxy) handleConnection(clientConn net.Conn) {
	defer p.activeConns.Done()
	defer clientConn.Close()

	clientAddr := clientConn.RemoteAddr().String()
	logger.Log.Info().
		Str("client", clientAddr).
		Msg("New client connection")

	// Get backend connection from pool
	backendConn, err := p.pool.Get()
	if err != nil {
		logger.Log.Error().
			Err(err).
			Str("client", clientAddr).
			Msg("Failed to get backend connection")
		return
	}

	// Return connection to pool when done (or close if error)
	defer func() {
		if backendConn != nil {
			p.pool.Put(backendConn)
		}
	}()

	logger.Log.Info().
		Str("client", clientAddr).
		Msg("Connected to backend, starting bidirectional forwarding")

	// Create channels for goroutine coordination
	done := make(chan error, 2)

	// Forward client -> backend
	go func() {
		_, err := io.Copy(backendConn, clientConn)
		done <- err
	}()

	// Forward backend -> client
	go func() {
		_, err := io.Copy(clientConn, backendConn)
		done <- err
	}()

	// Wait for either direction to complete
	err = <-done

	if err != nil && err != io.EOF {
		logger.Log.Error().
			Err(err).
			Str("client", clientAddr).
			Msg("Connection error")
	} else {
		logger.Log.Info().
			Str("client", clientAddr).
			Msg("Connection closed normally")
	}

	// Close both connections to trigger the other goroutine to finish
	clientConn.Close()
	backendConn.Close()

	// Wait for the other goroutine
	<-done
}

// isRunning checks if the proxy is running
func (p *Proxy) isRunning() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.running
}
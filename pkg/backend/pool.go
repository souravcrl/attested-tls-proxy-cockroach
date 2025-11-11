package backend

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/cockroachdb/attested-tls-proxy-cockroach/internal/config"
	"github.com/cockroachdb/attested-tls-proxy-cockroach/internal/logger"
)

// ConnectionPool manages backend connections to CockroachDB
type ConnectionPool struct {
	config      *config.BackendConfig
	tlsConfig   *tls.Config
	connections chan net.Conn
	mu          sync.Mutex
	closed      bool
}

// NewConnectionPool creates a new connection pool
func NewConnectionPool(cfg *config.BackendConfig, maxConnections int) (*ConnectionPool, error) {
	pool := &ConnectionPool{
		config:      cfg,
		connections: make(chan net.Conn, maxConnections),
	}

	// Setup TLS if enabled
	if cfg.TLS.Enabled {
		tlsConfig, err := loadTLSConfig(cfg.TLS)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS config: %w", err)
		}
		pool.tlsConfig = tlsConfig
	}

	return pool, nil
}

// Get retrieves a connection from the pool or creates a new one
func (p *ConnectionPool) Get() (net.Conn, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, fmt.Errorf("connection pool is closed")
	}
	p.mu.Unlock()

	// Try to get an existing connection
	select {
	case conn := <-p.connections:
		// Check if connection is still alive
		if isConnAlive(conn) {
			logger.Debug("Reusing pooled connection")
			return conn, nil
		}
		// Connection is dead, close it and create new one
		conn.Close()
	default:
		// No connections available
	}

	// Create new connection
	return p.createConnection()
}

// Put returns a connection to the pool
func (p *ConnectionPool) Put(conn net.Conn) {
	if conn == nil {
		return
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		conn.Close()
		return
	}
	p.mu.Unlock()

	select {
	case p.connections <- conn:
		// Connection returned to pool
		logger.Debug("Connection returned to pool")
	default:
		// Pool is full, close the connection
		conn.Close()
		logger.Debug("Pool full, closing connection")
	}
}

// Close closes all connections in the pool
func (p *ConnectionPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return
	}

	p.closed = true
	close(p.connections)

	// Close all pooled connections
	for conn := range p.connections {
		conn.Close()
	}
}

// createConnection establishes a new backend connection
func (p *ConnectionPool) createConnection() (net.Conn, error) {
	var conn net.Conn
	var err error

	// Connect via Unix socket if configured (preferred for same-VM)
	if p.config.UnixSocket != "" {
		logger.Log.Info().
			Str("socket", p.config.UnixSocket).
			Msg("Connecting to CockroachDB via Unix socket")

		conn, err = net.DialTimeout("unix", p.config.UnixSocket, 10*time.Second)
		if err != nil {
			return nil, fmt.Errorf("failed to connect via Unix socket: %w", err)
		}
	} else {
		// Connect via TCP
		addr := fmt.Sprintf("%s:%d", p.config.Host, p.config.Port)
		logger.Log.Info().
			Str("addr", addr).
			Msg("Connecting to CockroachDB via TCP")

		conn, err = net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to backend: %w", err)
		}
	}

	// Wrap with TLS if enabled
	if p.tlsConfig != nil {
		tlsConn := tls.Client(conn, p.tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}
		logger.Debug("TLS handshake completed with backend")
		return tlsConn, nil
	}

	return conn, nil
}

// loadTLSConfig loads TLS configuration from certificate files
func loadTLSConfig(cfg config.TLSConfig) (*tls.Config, error) {
	// Load CA certificate
	caCert, err := os.ReadFile(cfg.CACert)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA cert")
	}

	// Load client certificate and key
	cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load client cert/key: %w", err)
	}

	return &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// isConnAlive checks if a connection is still alive
func isConnAlive(conn net.Conn) bool {
	// Set a very short deadline to test the connection
	conn.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
	defer conn.SetReadDeadline(time.Time{})

	one := make([]byte, 1)
	_, err := conn.Read(one)

	// If we get a timeout, the connection is alive (no data to read)
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}

	// Any other error means the connection is dead
	return false
}
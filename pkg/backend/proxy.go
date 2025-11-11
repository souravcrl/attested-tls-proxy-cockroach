package backend

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/cockroachdb/attested-tls-proxy-cockroach/internal/config"
	"github.com/cockroachdb/attested-tls-proxy-cockroach/internal/logger"
	"github.com/cockroachdb/attested-tls-proxy-cockroach/pkg/attestation"
	"github.com/cockroachdb/attested-tls-proxy-cockroach/pkg/policy"
	tlsext "github.com/cockroachdb/attested-tls-proxy-cockroach/pkg/tls"
)

// Proxy represents the TLS proxy server
type Proxy struct {
	config            *config.Config
	listener          net.Listener
	pool              *ConnectionPool
	activeConns       sync.WaitGroup
	shutdown          chan struct{}
	mu                sync.Mutex
	running           bool
	verifier          *policy.Verifier
	attester          attestation.Attester
	tlsConfig         *tls.Config
	attestationStore  *attestation.AttestationStore
	connectionStats   map[string]*ConnectionStats
	statsMutex        sync.RWMutex
	attestationIDMap  sync.Map // Maps client address -> attestation ID
}

// ConnectionStats tracks bytes transferred for a connection
type ConnectionStats struct {
	BytesIn       int64
	BytesOut      int64
	ClientID      string
	AttestationID string
}

// countingConn wraps a net.Conn to count bytes read/written
type countingConn struct {
	net.Conn
	bytesRead    *int64
	bytesWritten *int64
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		*c.bytesRead += int64(n)
	}
	return n, err
}

func (c *countingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		*c.bytesWritten += int64(n)
	}
	return n, err
}

// NewProxy creates a new proxy instance
func NewProxy(cfg *config.Config) (*Proxy, error) {
	// Create connection pool (max 100 connections)
	pool, err := NewConnectionPool(&cfg.Proxy.Backend, 100)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Load attestation policy
	var policyObj *policy.Policy
	if cfg.Attestation.PolicyFile != "" {
		policyObj, err = policy.LoadPolicyFromFile(cfg.Attestation.PolicyFile)
		if err != nil {
			logger.Log.Warn().
				Err(err).
				Str("policy_file", cfg.Attestation.PolicyFile).
				Msg("Failed to load policy file, using defaults")
			policyObj = policy.NewDefaultPolicy()
		}
	} else {
		logger.Log.Info().Msg("No policy file specified, using default policy")
		policyObj = policy.NewDefaultPolicy()
	}

	// Create attestation verifier
	verifier, err := policy.NewVerifier(policyObj)
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}

	// Create attester
	attester, err := attestation.NewAttester(cfg.Attestation.Provider)
	if err != nil {
		return nil, fmt.Errorf("failed to create attester: %w", err)
	}

	// Create attestation store if storage is configured
	var store *attestation.AttestationStore
	if cfg.Attestation.Storage.DBPath != "" {
		store, err = attestation.NewAttestationStore(cfg.Attestation.Storage.DBPath)
		if err != nil {
			logger.Log.Warn().
				Err(err).
				Str("db_path", cfg.Attestation.Storage.DBPath).
				Msg("Failed to create attestation store, continuing without storage")
		} else {
			logger.Log.Info().
				Str("db_path", cfg.Attestation.Storage.DBPath).
				Msg("Attestation store initialized")
		}
	}

	// Create TLS configuration for accepting client connections
	tlsConfig, err := createTLSConfigWithVerifier(cfg, verifier, store, cfg.Proxy.NodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS config: %w", err)
	}

	logger.Log.Info().
		Str("provider", cfg.Attestation.Provider).
		Bool("tls_mutual_auth", tlsConfig != nil && tlsConfig.ClientAuth == tls.RequireAnyClientCert).
		Bool("attestation_storage", store != nil).
		Msg("Proxy initialized with attestation support")

	return &Proxy{
		config:           cfg,
		pool:             pool,
		shutdown:         make(chan struct{}),
		verifier:         verifier,
		attester:         attester,
		tlsConfig:        tlsConfig,
		attestationStore: store,
		connectionStats:  make(map[string]*ConnectionStats),
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

	// Create base TCP listener
	baseListener, err := net.Listen("tcp", p.config.Proxy.Listen)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", p.config.Proxy.Listen, err)
	}

	// Wrap with TLS if configured
	var listener net.Listener
	if p.tlsConfig != nil {
		listener = tls.NewListener(baseListener, p.tlsConfig)
		logger.Log.Info().
			Str("address", p.config.Proxy.Listen).
			Msg("Proxy started with TLS, waiting for connections")
	} else {
		listener = baseListener
		logger.Log.Info().
			Str("address", p.config.Proxy.Listen).
			Msg("Proxy started without TLS, waiting for connections")
	}

	p.listener = listener

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

// handleConnection handles a single client connection with attestation verification
func (p *Proxy) handleConnection(clientConn net.Conn) {
	defer p.activeConns.Done()
	defer clientConn.Close()

	clientAddr := clientConn.RemoteAddr().String()
	logger.Log.Info().
		Str("client", clientAddr).
		Msg("New client connection")

	var attestationID string
	var clientID string

	// If TLS is enabled, perform handshake (attestation verified via VerifyPeerCertificate callback)
	if tlsConn, ok := clientConn.(*tls.Conn); ok {
		// Perform TLS handshake
		// Attestation verification happens during handshake via VerifyPeerCertificate callback
		if err := tlsConn.Handshake(); err != nil {
			logger.Log.Error().
				Err(err).
				Str("client", clientAddr).
				Msg("TLS handshake failed (likely attestation verification failed)")
			return
		}

		// Handshake succeeded - attestation was verified during handshake
		state := tlsConn.ConnectionState()
		logger.Log.Info().
			Str("client", clientAddr).
			Int("peer_certs", len(state.PeerCertificates)).
			Msg("TLS handshake completed successfully with verified attestation")

		// Extract attestation to get client ID for tracking
		if len(state.PeerCertificates) > 0 {
			if evidence, err := tlsext.ExtractAttestationExtension(state.PeerCertificates[0]); err == nil {
				// Use first 8 bytes of measurement as client ID (matching CreateAttestationFromEvidence)
				measurementHex := hex.EncodeToString(evidence.Report.Measurement[:])
				clientID = measurementHex[:16] // First 8 bytes (16 hex chars)
				// Try to find the attestation ID from the store
				if p.attestationStore != nil {
					// Query for the most recent attestation with this measurement
					if attestations, err := p.attestationStore.GetByClientID(clientID); err == nil && len(attestations) > 0 {
						attestationID = attestations[0].ID
					}
				}
			}
		}
	} else {
		logger.Log.Warn().
			Str("client", clientAddr).
			Msg("Non-TLS connection - proceeding without attestation (development mode)")
	}

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
		Msg("Attestation verified - connected to backend, starting bidirectional forwarding")

	// Track bytes transferred
	var bytesClientToBackend int64
	var bytesBackendToClient int64

	// Create channels for goroutine coordination
	done := make(chan error, 2)

	// Forward client -> backend (counting bytes in)
	go func() {
		n, err := io.Copy(backendConn, clientConn)
		bytesClientToBackend = n
		done <- err
	}()

	// Forward backend -> client (counting bytes out)
	go func() {
		n, err := io.Copy(clientConn, backendConn)
		bytesBackendToClient = n
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

	// Update connection stats in store
	if p.attestationStore != nil && attestationID != "" {
		if err := p.attestationStore.UpdateConnectionStats(attestationID, bytesClientToBackend, bytesBackendToClient); err != nil {
			logger.Log.Error().
				Err(err).
				Str("attestation_id", attestationID).
				Int64("bytes_in", bytesClientToBackend).
				Int64("bytes_out", bytesBackendToClient).
				Msg("Failed to update connection statistics")
		} else {
			logger.Log.Debug().
				Str("attestation_id", attestationID).
				Str("client_id", clientID).
				Int64("bytes_in", bytesClientToBackend).
				Int64("bytes_out", bytesBackendToClient).
				Msg("Connection statistics updated")
		}
	}
}

// verifyClientAttestation extracts and verifies attestation from client certificate
func (p *Proxy) verifyClientAttestation(tlsConn *tls.Conn, clientAddr string) bool {
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		logger.Log.Warn().
			Str("client", clientAddr).
			Msg("No client certificate")
		return false
	}

	clientCert := state.PeerCertificates[0]

	// Extract attestation from certificate extension
	evidence, err := tlsext.ExtractAttestationExtension(clientCert)
	if err != nil {
		logger.Log.Warn().
			Err(err).
			Str("client", clientAddr).
			Msg("Failed to extract attestation extension")
		return false
	}

	logger.Log.Debug().
		Str("client", clientAddr).
		Str("tcb_version", evidence.Report.GetTCBVersion()).
		Bool("debug", evidence.Report.IsDebugEnabled()).
		Msg("Attestation extracted from certificate")

	// Verify attestation against policy
	result, err := p.verifier.Verify(evidence)
	if err != nil {
		logger.Log.Error().
			Err(err).
			Str("client", clientAddr).
			Msg("Attestation verification error")
		return false
	}

	if !result.Allowed {
		logger.Log.Warn().
			Str("client", clientAddr).
			Str("reason", result.Reason).
			Int("checks", len(result.Checks)).
			Msg("Attestation verification DENIED")

		// Log individual check failures
		for _, check := range result.Checks {
			if !check.Passed && check.Severity == "critical" {
				logger.Log.Warn().
					Str("check", check.Name).
					Str("message", check.Message).
					Msg("Failed critical check")
			}
		}

		return false
	}

	// Log successful verification
	logger.Log.Info().
		Str("client", clientAddr).
		Str("reason", result.Reason).
		Int("checks_passed", len(result.Checks)).
		Str("tcb_version", evidence.Report.GetTCBVersion()).
		Bool("debug_disabled", !evidence.Report.IsDebugEnabled()).
		Msg("Attestation verification ALLOWED")

	// Log individual check results at debug level
	for _, check := range result.Checks {
		logger.Log.Debug().
			Str("check", check.Name).
			Bool("passed", check.Passed).
			Str("severity", check.Severity).
			Str("message", check.Message).
			Msg("Check result")
	}

	return true
}

// GetAttestationStore returns the attestation store for API access
func (p *Proxy) GetAttestationStore() *attestation.AttestationStore {
	return p.attestationStore
}

// isRunning checks if the proxy is running
func (p *Proxy) isRunning() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.running
}

// createTLSConfigWithVerifier creates TLS configuration for the proxy with attestation verification
func createTLSConfigWithVerifier(cfg *config.Config, verifier *policy.Verifier, store *attestation.AttestationStore, nodeID string) (*tls.Config, error) {
	// Generate a self-signed server certificate for testing
	// In production, you would load real server certificates here
	certPEM, keyPEM, err := tlsext.GenerateTestCertificate("localhost")
	if err != nil {
		return nil, fmt.Errorf("failed to generate server certificate: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientAuth:   tls.RequireAnyClientCert, // Require client certificate with attestation
		MinVersion:   tls.VersionTLS13,          // RFC 9261 requires TLS 1.3
		// Verify client certificate and attestation during TLS handshake
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				logger.Log.Warn().Msg("No client certificates provided in handshake")
				return fmt.Errorf("no client certificate provided")
			}

			// Parse the client certificate
			clientCert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				logger.Log.Error().Err(err).Msg("Failed to parse client certificate in handshake")
				return fmt.Errorf("failed to parse client certificate: %w", err)
			}

			// Extract attestation from certificate extension
			evidence, err := tlsext.ExtractAttestationExtension(clientCert)
			if err != nil {
				logger.Log.Warn().
					Err(err).
					Msg("Failed to extract attestation extension in handshake")
				return fmt.Errorf("failed to extract attestation: %w", err)
			}

			logger.Log.Debug().
				Str("tcb_version", evidence.Report.GetTCBVersion()).
				Bool("debug", evidence.Report.IsDebugEnabled()).
				Msg("Attestation extracted from certificate, verifying against policy")

			// Verify attestation against policy
			result, err := verifier.Verify(evidence)
			if err != nil {
				logger.Log.Error().
					Err(err).
					Msg("Attestation verification error during handshake")
				return fmt.Errorf("attestation verification failed: %w", err)
			}

			if !result.Allowed {
				logger.Log.Warn().
					Str("reason", result.Reason).
					Int("checks", len(result.Checks)).
					Msg("Attestation verification DENIED during handshake")

				// Log individual check failures at debug level
				for _, check := range result.Checks {
					if !check.Passed && check.Severity == "critical" {
						logger.Log.Debug().
							Str("check", check.Name).
							Str("message", check.Message).
							Msg("Failed critical check during handshake")
					}
				}

				// Record denied attestation in store if available
				if store != nil {
					attestationRecord := attestation.CreateAttestationFromEvidence(evidence, "denied", result.Reason, nodeID)
					if err := store.RecordAttestation(attestationRecord); err != nil {
						logger.Log.Error().
							Err(err).
							Str("client_id", attestationRecord.ClientID).
							Msg("Failed to record denied attestation in store")
					}
				}

				return fmt.Errorf("attestation verification failed: %s", result.Reason)
			}

			logger.Log.Info().
				Str("reason", result.Reason).
				Int("checks_passed", len(result.Checks)).
				Str("tcb_version", evidence.Report.GetTCBVersion()).
				Msg("Attestation verification ALLOWED during handshake")

			// Record attestation in store if available
			if store != nil {
				attestationRecord := attestation.CreateAttestationFromEvidence(evidence, "allowed", result.Reason, nodeID)
				if err := store.RecordAttestation(attestationRecord); err != nil {
					logger.Log.Error().
						Err(err).
						Str("client_id", attestationRecord.ClientID).
						Msg("Failed to record attestation in store")
				} else {
					logger.Log.Debug().
						Str("client_id", attestationRecord.ClientID).
						Str("measurement", attestationRecord.Measurement).
						Msg("Attestation recorded in store")
				}
			}

			return nil
		},
	}

	// Load CA certificates if specified
	if cfg.Proxy.Backend.TLS.CACert != "" {
		caCert, err := os.ReadFile(cfg.Proxy.Backend.TLS.CACert)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}

		tlsConfig.ClientCAs = caCertPool
	}

	logger.Log.Info().
		Str("min_version", "TLS 1.3").
		Bool("require_client_cert", true).
		Bool("verify_attestation_in_handshake", true).
		Msg("TLS configuration created with attestation verification")

	return tlsConfig, nil
}
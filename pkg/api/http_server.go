package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/cockroachdb/attested-tls-proxy-cockroach/internal/logger"
	"github.com/cockroachdb/attested-tls-proxy-cockroach/pkg/attestation"
)

// nonceEntry stores a nonce with expiration
type nonceEntry struct {
	nonce     []byte
	createdAt time.Time
}

// Server provides HTTP API for attestation data
type Server struct {
	store       *attestation.AttestationStore
	proxyNodeID string
	mux         *http.ServeMux
	nonces      map[string]*nonceEntry // Map of nonce hex -> entry
	nonceMutex  sync.RWMutex
	nonceTTL    time.Duration
}

// NewServer creates a new HTTP API server
func NewServer(store *attestation.AttestationStore, proxyNodeID string) *Server {
	s := &Server{
		store:       store,
		proxyNodeID: proxyNodeID,
		mux:         http.NewServeMux(),
		nonces:      make(map[string]*nonceEntry),
		nonceTTL:    5 * time.Minute, // 5 minute expiration for nonces
	}

	s.registerHandlers()

	// Start cleanup goroutine for expired nonces
	go s.cleanupExpiredNonces()

	return s
}

// registerHandlers sets up all HTTP route handlers
func (s *Server) registerHandlers() {
	s.mux.HandleFunc("/api/v1/nonce", s.handleNonce)
	s.mux.HandleFunc("/api/v1/attestations", s.handleAttestations)
	s.mux.HandleFunc("/api/v1/clients", s.handleClients)
	s.mux.HandleFunc("/api/v1/clients/active", s.handleActiveClients)
	s.mux.HandleFunc("/api/v1/stats/measurements", s.handleMeasurementStats)
	s.mux.HandleFunc("/api/v1/stats/overview", s.handleStatsOverview)
	s.mux.HandleFunc("/api/v1/health", s.handleHealth)
	s.mux.HandleFunc("/api/v1/node/info", s.handleNodeInfo)
}

// Start starts the HTTP server on the given address
func (s *Server) Start(addr string) error {
	logger.Log.Info().
		Str("address", addr).
		Str("proxy_node_id", s.proxyNodeID).
		Msg("Starting HTTP API server")

	return http.ListenAndServe(addr, s.mux)
}

// handleAttestations returns recent attestation events
func (s *Server) handleAttestations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse limit parameter
	limit := 100
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	}

	attestations, err := s.store.GetRecentAttestations(limit)
	if err != nil {
		logger.Log.Error().Err(err).Msg("Failed to retrieve attestations")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"proxy_node_id": s.proxyNodeID,
		"count":         len(attestations),
		"attestations":  attestations,
		"timestamp":     time.Now().Format(time.RFC3339),
	}

	s.respondJSON(w, response)
}

// handleClients returns client attestation records
func (s *Server) handleClients(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check for client_id parameter
	clientID := r.URL.Query().Get("client_id")
	if clientID != "" {
		// Get specific client's attestations
		attestations, err := s.store.GetByClientID(clientID)
		if err != nil {
			logger.Log.Error().Err(err).Str("client_id", clientID).Msg("Failed to retrieve client attestations")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		response := map[string]interface{}{
			"proxy_node_id": s.proxyNodeID,
			"client_id":     clientID,
			"count":         len(attestations),
			"attestations":  attestations,
			"timestamp":     time.Now().Format(time.RFC3339),
		}

		s.respondJSON(w, response)
		return
	}

	// Otherwise return recent attestations
	limit := 100
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	}

	attestations, err := s.store.GetRecentAttestations(limit)
	if err != nil {
		logger.Log.Error().Err(err).Msg("Failed to retrieve clients")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"proxy_node_id": s.proxyNodeID,
		"count":         len(attestations),
		"clients":       attestations,
		"timestamp":     time.Now().Format(time.RFC3339),
	}

	s.respondJSON(w, response)
}

// handleActiveClients returns currently active (connected) clients
func (s *Server) handleActiveClients(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clients, err := s.store.GetActiveClients()
	if err != nil {
		logger.Log.Error().Err(err).Msg("Failed to retrieve active clients")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"proxy_node_id":  s.proxyNodeID,
		"count":          len(clients),
		"active_clients": clients,
		"timestamp":      time.Now().Format(time.RFC3339),
	}

	s.respondJSON(w, response)
}

// handleMeasurementStats returns statistics grouped by measurement hash
func (s *Server) handleMeasurementStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats, err := s.store.GetStatsByMeasurement()
	if err != nil {
		logger.Log.Error().Err(err).Msg("Failed to retrieve measurement stats")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"proxy_node_id": s.proxyNodeID,
		"measurements":  stats,
		"timestamp":     time.Now().Format(time.RFC3339),
	}

	s.respondJSON(w, response)
}

// handleStatsOverview returns overall statistics
func (s *Server) handleStatsOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats, err := s.store.GetStatistics()
	if err != nil {
		logger.Log.Error().Err(err).Msg("Failed to retrieve statistics")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	stats["proxy_node_id"] = s.proxyNodeID
	stats["timestamp"] = time.Now().Format(time.RFC3339)

	s.respondJSON(w, stats)
}

// handleHealth returns health check status
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Check database connectivity
	if _, err := s.store.GetStatistics(); err != nil {
		http.Error(w, "Database unhealthy", http.StatusServiceUnavailable)
		return
	}

	response := map[string]interface{}{
		"status":        "healthy",
		"proxy_node_id": s.proxyNodeID,
		"timestamp":     time.Now().Format(time.RFC3339),
	}

	s.respondJSON(w, response)
}

// handleNodeInfo returns information about this proxy node
func (s *Server) handleNodeInfo(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"node_id":   s.proxyNodeID,
		"version":   "1.0.0", // TODO: Get from build info
		"timestamp": time.Now().Format(time.RFC3339),
	}

	s.respondJSON(w, response)
}

// respondJSON writes a JSON response
func (s *Server) respondJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Proxy-Node-ID", s.proxyNodeID)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		logger.Log.Error().Err(err).Msg("Failed to encode JSON response")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// Response types for API documentation

// AttestationsResponse represents the response for /api/v1/attestations
type AttestationsResponse struct {
	ProxyNodeID  string                            `json:"proxy_node_id"`
	Count        int                               `json:"count"`
	Attestations []*attestation.ClientAttestation  `json:"attestations"`
	Timestamp    string                            `json:"timestamp"`
}

// ClientsResponse represents the response for /api/v1/clients
type ClientsResponse struct {
	ProxyNodeID string                            `json:"proxy_node_id"`
	Count       int                               `json:"count"`
	Clients     []*attestation.ClientAttestation  `json:"clients"`
	Timestamp   string                            `json:"timestamp"`
}

// ActiveClientsResponse represents the response for /api/v1/clients/active
type ActiveClientsResponse struct {
	ProxyNodeID   string                            `json:"proxy_node_id"`
	Count         int                               `json:"count"`
	ActiveClients []*attestation.ClientAttestation  `json:"active_clients"`
	Timestamp     string                            `json:"timestamp"`
}

// MeasurementStatsResponse represents the response for /api/v1/stats/measurements
type MeasurementStatsResponse struct {
	ProxyNodeID  string         `json:"proxy_node_id"`
	Measurements map[string]int `json:"measurements"`
	Timestamp    string         `json:"timestamp"`
}

// HealthResponse represents the response for /api/v1/health
type HealthResponse struct {
	Status      string `json:"status"`
	ProxyNodeID string `json:"proxy_node_id"`
	Timestamp   string `json:"timestamp"`
}

// NodeInfoResponse represents the response for /api/v1/node/info
type NodeInfoResponse struct {
	NodeID    string `json:"node_id"`
	Version   string `json:"version"`
	Timestamp string `json:"timestamp"`
}

// handleNonce generates a fresh nonce for attestation
func (s *Server) handleNonce(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Generate 32-byte random nonce
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		logger.Log.Error().Err(err).Msg("Failed to generate nonce")
		http.Error(w, "Failed to generate nonce", http.StatusInternalServerError)
		return
	}

	// Store nonce with expiration
	nonceHex := hex.EncodeToString(nonce)
	entry := &nonceEntry{
		nonce:     nonce,
		createdAt: time.Now(),
	}

	s.nonceMutex.Lock()
	s.nonces[nonceHex] = entry
	s.nonceMutex.Unlock()

	logger.Log.Debug().
		Str("nonce_hex", nonceHex[:16]+"...").
		Msg("Generated nonce for attestation")

	response := map[string]interface{}{
		"nonce":      nonceHex,
		"expires_in": int(s.nonceTTL.Seconds()),
		"timestamp":  time.Now().Format(time.RFC3339),
	}

	s.respondJSON(w, response)
}

// ValidateNonce checks if a nonce exists and hasn't expired
func (s *Server) ValidateNonce(nonce []byte) bool {
	nonceHex := hex.EncodeToString(nonce)

	s.nonceMutex.RLock()
	entry, exists := s.nonces[nonceHex]
	s.nonceMutex.RUnlock()

	if !exists {
		return false
	}

	// Check if expired
	if time.Since(entry.createdAt) > s.nonceTTL {
		// Clean up expired nonce
		s.nonceMutex.Lock()
		delete(s.nonces, nonceHex)
		s.nonceMutex.Unlock()
		return false
	}

	// Nonce is valid - consume it (one-time use)
	s.nonceMutex.Lock()
	delete(s.nonces, nonceHex)
	s.nonceMutex.Unlock()

	return true
}

// cleanupExpiredNonces periodically removes expired nonces
func (s *Server) cleanupExpiredNonces() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.nonceMutex.Lock()
		now := time.Now()
		for nonceHex, entry := range s.nonces {
			if now.Sub(entry.createdAt) > s.nonceTTL {
				delete(s.nonces, nonceHex)
			}
		}
		s.nonceMutex.Unlock()
	}
}
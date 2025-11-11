package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/cockroachdb/attested-tls-proxy-cockroach/internal/logger"
	"github.com/cockroachdb/attested-tls-proxy-cockroach/pkg/attestation"
)

// Server provides HTTP API for attestation data
type Server struct {
	store       *attestation.AttestationStore
	proxyNodeID string
	mux         *http.ServeMux
}

// NewServer creates a new HTTP API server
func NewServer(store *attestation.AttestationStore, proxyNodeID string) *Server {
	s := &Server{
		store:       store,
		proxyNodeID: proxyNodeID,
		mux:         http.NewServeMux(),
	}

	s.registerHandlers()
	return s
}

// registerHandlers sets up all HTTP route handlers
func (s *Server) registerHandlers() {
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
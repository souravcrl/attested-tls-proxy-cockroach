package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
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
	// API endpoints
	s.mux.HandleFunc("/api/v1/nonce", s.handleNonce)
	s.mux.HandleFunc("/api/v1/attestations", s.handleAttestations)
	s.mux.HandleFunc("/api/v1/clients", s.handleClients)
	s.mux.HandleFunc("/api/v1/clients/active", s.handleActiveClients)
	s.mux.HandleFunc("/api/v1/stats/measurements", s.handleMeasurementStats)
	s.mux.HandleFunc("/api/v1/stats/overview", s.handleStatsOverview)
	s.mux.HandleFunc("/api/v1/health", s.handleHealth)
	s.mux.HandleFunc("/api/v1/node/info", s.handleNodeInfo)
	s.mux.HandleFunc("/api/aggregated", s.handleAggregated)

	// Serve React dashboard static files with CORS headers
	fs := http.FileServer(http.Dir("dashboard-ui/dist"))
	s.mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add CORS headers for static files too
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		fs.ServeHTTP(w, r)
	}))
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
	// Add CORS headers to allow cross-origin requests
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
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

// handleAggregated returns aggregated data for the React dashboard
// This endpoint aggregates data from all proxy nodes in the cluster
func (s *Server) handleAggregated(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Define all proxy nodes in the cluster
	proxyNodes := []struct {
		ID      string
		Address string
		APIPort string
	}{
		{"proxy-1", "localhost:26257", "localhost:8081"},
		{"proxy-2", "localhost:26267", "localhost:8082"},
		{"proxy-3", "localhost:26277", "localhost:8083"},
	}

	// Aggregate data from all nodes
	var allClients []map[string]interface{}
	var totalActiveClients int
	attestationsByProxy := make(map[string]int)
	measurementStats := make(map[string]int)
	proxyNodesInfo := make([]map[string]interface{}, 0)

	// Fetch data from each proxy node
	client := &http.Client{Timeout: 2 * time.Second}
	for _, node := range proxyNodes {
		nodeHealthy := true
		statsURL := "http://" + node.APIPort + "/api/v1/stats/overview"
		measurementsURL := "http://" + node.APIPort + "/api/v1/stats/measurements"
		attestationsURL := "http://" + node.APIPort + "/api/v1/attestations?limit=100"

		// Fetch overview stats
		statsResp, err := client.Get(statsURL)
		if err != nil {
			logger.Log.Warn().Err(err).Str("node_id", node.ID).Msg("Failed to fetch stats from proxy node")
			nodeHealthy = false
		} else {
			defer statsResp.Body.Close()
			var stats map[string]interface{}
			if err := json.NewDecoder(statsResp.Body).Decode(&stats); err == nil {
				// Add to active clients count
				if activeCount, ok := stats["active_connections"].(float64); ok {
					totalActiveClients += int(activeCount)
				}

				// Add to attestations by proxy
				if totalAttest, ok := stats["total_attestations"].(float64); ok {
					attestationsByProxy[node.ID] = int(totalAttest)
				}
			}
		}

		// Fetch measurement stats separately
		measurementResp, err := client.Get(measurementsURL)
		if err != nil {
			logger.Log.Warn().Err(err).Str("node_id", node.ID).Msg("Failed to fetch measurements from proxy node")
		} else {
			defer measurementResp.Body.Close()
			var measurementData map[string]interface{}
			if err := json.NewDecoder(measurementResp.Body).Decode(&measurementData); err == nil {
				// Merge measurement stats
				if measurements, ok := measurementData["measurements"].(map[string]interface{}); ok {
					for measurement, count := range measurements {
						if c, ok := count.(float64); ok {
							measurementStats[measurement] += int(c)
						}
					}
				}
			}
		}

		// Fetch attestations
		attestResp, err := client.Get(attestationsURL)
		if err != nil {
			logger.Log.Warn().Err(err).Str("node_id", node.ID).Msg("Failed to fetch attestations from proxy node")
			nodeHealthy = false
		} else {
			defer attestResp.Body.Close()
			var attestData map[string]interface{}
			if err := json.NewDecoder(attestResp.Body).Decode(&attestData); err == nil {
				if attestations, ok := attestData["attestations"].([]interface{}); ok {
					for _, att := range attestations {
						if attMap, ok := att.(map[string]interface{}); ok {
							// Format client data
							formattedClient := map[string]interface{}{
								"id":              attMap["id"],
								"client_id":       attMap["client_id"],
								"measurement":     attMap["measurement"],
								"tcb_version":     attMap["tcb_version"],
								"debug_enabled":   attMap["debug_enabled"],
								"smt_enabled":     attMap["smt_enabled"],
								"connected_at":    attMap["connected_at"],
								"disconnected_at": attMap["disconnected_at"],
								"proxy_address":   node.ID, // Use node ID instead of address
								"verify_result":   attMap["verify_result"],
								"verify_reason":   attMap["verify_reason"],
								"bytes_in":        attMap["bytes_in"],
								"bytes_out":       attMap["bytes_out"],
								"family_id":       attMap["family_id"],
								"image_id":        attMap["image_id"],
								"chip_id":         attMap["chip_id"],
							}
							allClients = append(allClients, formattedClient)
						}
					}
				}
			}
		}

		// Add node info
		proxyNodesInfo = append(proxyNodesInfo, map[string]interface{}{
			"id":      node.ID,
			"address": node.Address,
			"healthy": nodeHealthy,
		})
	}

	// Compute additional statistics from all clients
	tcbVersionStats := make(map[string]int)
	verifyResultStats := make(map[string]int)
	debugEnabledCount := 0
	smtEnabledCount := 0
	failureTypeStats := make(map[string]int)

	for _, client := range allClients {
		// TCB version distribution
		if tcbVersion, ok := client["tcb_version"].(string); ok && tcbVersion != "" {
			tcbVersionStats[tcbVersion]++
		}

		// Verify result distribution
		if verifyResult, ok := client["verify_result"].(string); ok && verifyResult != "" {
			verifyResultStats[verifyResult]++
		}

		// Debug enabled count
		if debugEnabled, ok := client["debug_enabled"].(bool); ok && debugEnabled {
			debugEnabledCount++
		}

		// SMT enabled count
		if smtEnabled, ok := client["smt_enabled"].(bool); ok && smtEnabled {
			smtEnabledCount++
		}

		// Failure type statistics (for denied clients)
		if verifyResult, ok := client["verify_result"].(string); ok && verifyResult == "denied" {
			if verifyReason, ok := client["verify_reason"].(string); ok && verifyReason != "" {
				// Extract the main failure type from the reason
				// Examples:
				// "Critical check failed: nonce_validation - ..." -> "nonce_validation"
				// "Critical check failed: debug_mode - ..." -> "debug_mode"
				failureType := extractFailureType(verifyReason)
				failureTypeStats[failureType]++
			}
		}
	}

	response := map[string]interface{}{
		"total_clients":         len(allClients),
		"active_clients":        totalActiveClients,
		"attestations_by_proxy": attestationsByProxy,
		"measurement_stats":     measurementStats,
		"failure_type_stats":    failureTypeStats,
		"tcb_version_stats":     tcbVersionStats,
		"verify_result_stats":   verifyResultStats,
		"debug_enabled_count":   debugEnabledCount,
		"smt_enabled_count":     smtEnabledCount,
		"clients":               allClients,
		"proxy_nodes":           proxyNodesInfo,
		"last_updated":          time.Now().Format(time.RFC3339),
	}

	s.respondJSON(w, response)
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

// extractFailureType extracts the failure type from a verify_reason string
func extractFailureType(verifyReason string) string {
	// Extract the check name from messages like:
	// "Critical check failed: nonce_validation - Nonce not recognized..."
	// "Critical check failed: debug_mode - Debug mode is enabled..."
	// "Critical check failed: tcb_version - TCB version 1.40.0 is below..."
	// "Critical check failed: guest_policy - Guest policy violations: debug is enabled, SMT is enabled"

	// Look for pattern "Critical check failed: <check_name> -"
	if idx := strings.Index(verifyReason, "Critical check failed: "); idx >= 0 {
		rest := verifyReason[idx+len("Critical check failed: "):]
		if dashIdx := strings.Index(rest, " -"); dashIdx > 0 {
			checkName := rest[:dashIdx]

			// Special handling for guest_policy - parse specific violations
			if checkName == "guest_policy" {
				details := rest[dashIdx+3:] // Skip " - "
				// Check for specific violations
				if strings.Contains(details, "debug is enabled") {
					return "debug_mode"
				}
				if strings.Contains(details, "SMT is enabled") {
					return "smt"
				}
			}

			return checkName
		}
	}

	// If pattern not found, return a sanitized version of the reason
	if len(verifyReason) > 50 {
		return verifyReason[:50]
	}
	return verifyReason
}
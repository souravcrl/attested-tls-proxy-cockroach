package attestation

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/cockroachdb/attested-tls-proxy-cockroach/internal/logger"
)

// AttestationStore manages persistent storage of client attestation data
type AttestationStore struct {
	db *sql.DB
}

// ClientAttestation represents a client's attestation record
type ClientAttestation struct {
	ID             string     `json:"id"`
	ClientID       string     `json:"client_id"`        // Derived from measurement
	Measurement    string     `json:"measurement"`       // SHA-384 hex
	TCBVersion     string     `json:"tcb_version"`
	DebugEnabled   bool       `json:"debug_enabled"`
	SMTEnabled     bool       `json:"smt_enabled"`
	Nonce          string     `json:"nonce"`
	Timestamp      time.Time  `json:"timestamp"`
	VerifyResult   string     `json:"verify_result"`    // "allowed" or "denied"
	VerifyReason   string     `json:"verify_reason"`
	ConnectedAt    time.Time  `json:"connected_at"`
	DisconnectedAt *time.Time `json:"disconnected_at,omitempty"`
	BytesIn        int64      `json:"bytes_in"`
	BytesOut       int64      `json:"bytes_out"`
	ProxyNodeID    string     `json:"proxy_node_id"`    // This proxy's ID
}

// NewAttestationStore creates a new attestation store with SQLite backend
func NewAttestationStore(dbPath string) (*AttestationStore, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Enable WAL mode for better concurrent access
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, fmt.Errorf("failed to enable WAL mode: %w", err)
	}

	// Create schema
	schema := `
		CREATE TABLE IF NOT EXISTS client_attestations (
			id TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			measurement TEXT NOT NULL,
			tcb_version TEXT,
			debug_enabled BOOLEAN,
			smt_enabled BOOLEAN,
			nonce TEXT,
			timestamp DATETIME,
			verify_result TEXT,
			verify_reason TEXT,
			connected_at DATETIME,
			disconnected_at DATETIME,
			bytes_in INTEGER DEFAULT 0,
			bytes_out INTEGER DEFAULT 0,
			proxy_node_id TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE INDEX IF NOT EXISTS idx_client_id ON client_attestations(client_id);
		CREATE INDEX IF NOT EXISTS idx_connected_at ON client_attestations(connected_at);
		CREATE INDEX IF NOT EXISTS idx_verify_result ON client_attestations(verify_result);
		CREATE INDEX IF NOT EXISTS idx_measurement ON client_attestations(measurement);
		CREATE INDEX IF NOT EXISTS idx_proxy_node_id ON client_attestations(proxy_node_id);
	`

	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	logger.Log.Info().
		Str("db_path", dbPath).
		Msg("Attestation store initialized")

	return &AttestationStore{db: db}, nil
}

// RecordAttestation stores a client attestation record
func (s *AttestationStore) RecordAttestation(att *ClientAttestation) error {
	query := `
		INSERT INTO client_attestations (
			id, client_id, measurement, tcb_version, debug_enabled, smt_enabled,
			nonce, timestamp, verify_result, verify_reason, connected_at, proxy_node_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := s.db.Exec(query,
		att.ID, att.ClientID, att.Measurement, att.TCBVersion, att.DebugEnabled,
		att.SMTEnabled, att.Nonce, att.Timestamp, att.VerifyResult, att.VerifyReason,
		att.ConnectedAt, att.ProxyNodeID)

	if err != nil {
		return fmt.Errorf("failed to insert attestation: %w", err)
	}

	logger.Log.Debug().
		Str("id", att.ID).
		Str("client_id", att.ClientID).
		Str("verify_result", att.VerifyResult).
		Msg("Attestation recorded")

	return nil
}

// UpdateConnectionStats updates connection statistics when a client disconnects
func (s *AttestationStore) UpdateConnectionStats(id string, bytesIn, bytesOut int64) error {
	query := `
		UPDATE client_attestations
		SET bytes_in = ?, bytes_out = ?, disconnected_at = ?
		WHERE id = ?
	`

	result, err := s.db.Exec(query, bytesIn, bytesOut, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to update connection stats: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("attestation record not found: %s", id)
	}

	logger.Log.Debug().
		Str("id", id).
		Int64("bytes_in", bytesIn).
		Int64("bytes_out", bytesOut).
		Msg("Connection stats updated")

	return nil
}

// GetRecentAttestations retrieves recent attestation records
func (s *AttestationStore) GetRecentAttestations(limit int) ([]*ClientAttestation, error) {
	query := `
		SELECT id, client_id, measurement, tcb_version, debug_enabled, smt_enabled,
		       nonce, timestamp, verify_result, verify_reason, connected_at,
		       disconnected_at, bytes_in, bytes_out, proxy_node_id
		FROM client_attestations
		ORDER BY connected_at DESC
		LIMIT ?
	`

	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query attestations: %w", err)
	}
	defer rows.Close()

	return s.scanAttestations(rows)
}

// GetActiveClients retrieves currently active (connected) clients
func (s *AttestationStore) GetActiveClients() ([]*ClientAttestation, error) {
	query := `
		SELECT id, client_id, measurement, tcb_version, debug_enabled, smt_enabled,
		       nonce, timestamp, verify_result, verify_reason, connected_at,
		       disconnected_at, bytes_in, bytes_out, proxy_node_id
		FROM client_attestations
		WHERE disconnected_at IS NULL AND verify_result = 'allowed'
		ORDER BY connected_at DESC
	`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query active clients: %w", err)
	}
	defer rows.Close()

	return s.scanAttestations(rows)
}

// GetByClientID retrieves all attestation records for a specific client
func (s *AttestationStore) GetByClientID(clientID string) ([]*ClientAttestation, error) {
	query := `
		SELECT id, client_id, measurement, tcb_version, debug_enabled, smt_enabled,
		       nonce, timestamp, verify_result, verify_reason, connected_at,
		       disconnected_at, bytes_in, bytes_out, proxy_node_id
		FROM client_attestations
		WHERE client_id = ?
		ORDER BY connected_at DESC
	`

	rows, err := s.db.Query(query, clientID)
	if err != nil {
		return nil, fmt.Errorf("failed to query by client ID: %w", err)
	}
	defer rows.Close()

	return s.scanAttestations(rows)
}

// GetStatsByMeasurement returns statistics grouped by measurement hash
func (s *AttestationStore) GetStatsByMeasurement() (map[string]int, error) {
	query := `
		SELECT measurement, COUNT(*) as count
		FROM client_attestations
		WHERE verify_result = 'allowed'
		GROUP BY measurement
	`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query measurement stats: %w", err)
	}
	defer rows.Close()

	stats := make(map[string]int)
	for rows.Next() {
		var measurement string
		var count int
		if err := rows.Scan(&measurement, &count); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		stats[measurement] = count
	}

	return stats, rows.Err()
}

// GetStatistics returns overall statistics
func (s *AttestationStore) GetStatistics() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Total attestations
	var total int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM client_attestations").Scan(&total); err != nil {
		return nil, err
	}
	stats["total_attestations"] = total

	// Allowed vs denied
	var allowed, denied int
	s.db.QueryRow("SELECT COUNT(*) FROM client_attestations WHERE verify_result = 'allowed'").Scan(&allowed)
	s.db.QueryRow("SELECT COUNT(*) FROM client_attestations WHERE verify_result = 'denied'").Scan(&denied)
	stats["allowed"] = allowed
	stats["denied"] = denied

	// Active connections
	var active int
	s.db.QueryRow("SELECT COUNT(*) FROM client_attestations WHERE disconnected_at IS NULL AND verify_result = 'allowed'").Scan(&active)
	stats["active_connections"] = active

	return stats, nil
}

// Cleanup removes old attestation records
func (s *AttestationStore) Cleanup(retentionDays int) (int64, error) {
	cutoff := time.Now().AddDate(0, 0, -retentionDays)

	query := `
		DELETE FROM client_attestations
		WHERE connected_at < ? AND disconnected_at IS NOT NULL
	`

	result, err := s.db.Exec(query, cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup old records: %w", err)
	}

	rowsDeleted, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}

	logger.Log.Info().
		Int64("rows_deleted", rowsDeleted).
		Int("retention_days", retentionDays).
		Msg("Attestation store cleanup completed")

	return rowsDeleted, nil
}

// Close closes the database connection
func (s *AttestationStore) Close() error {
	return s.db.Close()
}

// scanAttestations is a helper to scan attestation records from query results
func (s *AttestationStore) scanAttestations(rows *sql.Rows) ([]*ClientAttestation, error) {
	var attestations []*ClientAttestation

	for rows.Next() {
		att := &ClientAttestation{}
		err := rows.Scan(
			&att.ID, &att.ClientID, &att.Measurement, &att.TCBVersion,
			&att.DebugEnabled, &att.SMTEnabled, &att.Nonce, &att.Timestamp,
			&att.VerifyResult, &att.VerifyReason, &att.ConnectedAt,
			&att.DisconnectedAt, &att.BytesIn, &att.BytesOut, &att.ProxyNodeID,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan attestation: %w", err)
		}
		attestations = append(attestations, att)
	}

	return attestations, rows.Err()
}

// CreateAttestationFromEvidence creates a ClientAttestation record from evidence and verification result
func CreateAttestationFromEvidence(
	evidence *AttestationEvidence,
	verifyResult string,
	verifyReason string,
	proxyNodeID string,
) *ClientAttestation {
	// Use first 8 bytes of measurement as client ID
	measurementHex := hex.EncodeToString(evidence.Report.Measurement[:])
	clientID := measurementHex[:16] // First 8 bytes (16 hex chars)

	return &ClientAttestation{
		ID:           generateID(),
		ClientID:     clientID,
		Measurement:  measurementHex,
		TCBVersion:   evidence.Report.GetTCBVersion(),
		DebugEnabled: evidence.Report.IsDebugEnabled(),
		SMTEnabled:   evidence.Report.IsSMTEnabled(),
		Nonce:        hex.EncodeToString(evidence.Nonce),
		Timestamp:    time.Unix(evidence.Timestamp, 0),
		VerifyResult: verifyResult,
		VerifyReason: verifyReason,
		ConnectedAt:  time.Now(),
		ProxyNodeID:  proxyNodeID,
	}
}

// generateID generates a unique ID for attestation records
func generateID() string {
	// Simple ID generation using timestamp and random component
	return fmt.Sprintf("%d-%s", time.Now().UnixNano(), randomString(8))
}

func randomString(n int) string {
	// Simple implementation - in production, use crypto/rand
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
	}
	return string(b)
}

// MarshalJSON implements custom JSON marshaling for better API responses
func (a *ClientAttestation) MarshalJSON() ([]byte, error) {
	type Alias ClientAttestation
	return json.Marshal(&struct {
		*Alias
		Timestamp      string  `json:"timestamp"`
		ConnectedAt    string  `json:"connected_at"`
		DisconnectedAt *string `json:"disconnected_at,omitempty"`
	}{
		Alias:      (*Alias)(a),
		Timestamp:  a.Timestamp.Format(time.RFC3339),
		ConnectedAt: a.ConnectedAt.Format(time.RFC3339),
		DisconnectedAt: func() *string {
			if a.DisconnectedAt != nil {
				t := a.DisconnectedAt.Format(time.RFC3339)
				return &t
			}
			return nil
		}(),
	})
}
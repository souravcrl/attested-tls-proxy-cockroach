package helpers

import (
	"database/sql"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver
)

// TestCRDB manages a CockroachDB instance for testing
type TestCRDB struct {
	Port      int
	HTTPPort  int
	DataDir   string
	Process   *exec.Cmd
	LogFile   *os.File
	Binary    string
}

// CRDBConfig configures the test CockroachDB instance
type CRDBConfig struct {
	Binary   string // Path to cockroach binary (default: "cockroach")
	Insecure bool   // Run in insecure mode (default: true for tests)
	Port     int    // SQL port (0 = random)
	HTTPPort int    // HTTP port (0 = random)
}

// DefaultCRDBConfig returns default configuration for testing
func DefaultCRDBConfig() *CRDBConfig {
	// Try to find local cockroach binary first
	binary := "cockroach"
	if _, err := os.Stat("../../cockroach"); err == nil {
		binary = "../../cockroach"
	} else if _, err := os.Stat("./cockroach"); err == nil {
		binary = "./cockroach"
	}

	return &CRDBConfig{
		Binary:   binary,
		Insecure: true,
		Port:     0, // Random port
		HTTPPort: 0, // Random port
	}
}

// StartTestCRDB starts a CockroachDB instance for testing
func StartTestCRDB() (*TestCRDB, error) {
	return StartTestCRDBWithConfig(DefaultCRDBConfig())
}

// StartTestCRDBWithConfig starts a CockroachDB instance with custom configuration
func StartTestCRDBWithConfig(cfg *CRDBConfig) (*TestCRDB, error) {
	// Create temporary data directory
	dataDir, err := os.MkdirTemp("", "crdb-test-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	// Create log file
	logFile, err := os.Create(filepath.Join(dataDir, "crdb.log"))
	if err != nil {
		os.RemoveAll(dataDir)
		return nil, fmt.Errorf("failed to create log file: %w", err)
	}

	// Find available ports if not specified
	sqlPort := cfg.Port
	httpPort := cfg.HTTPPort

	if sqlPort == 0 {
		sqlPort, err = findAvailablePort()
		if err != nil {
			logFile.Close()
			os.RemoveAll(dataDir)
			return nil, fmt.Errorf("failed to find SQL port: %w", err)
		}
	}

	if httpPort == 0 {
		httpPort, err = findAvailablePort()
		if err != nil {
			logFile.Close()
			os.RemoveAll(dataDir)
			return nil, fmt.Errorf("failed to find HTTP port: %w", err)
		}
	}

	// Build command
	args := []string{
		"start-single-node",
		"--store=" + dataDir,
		"--listen-addr=localhost:" + strconv.Itoa(sqlPort),
		"--http-addr=localhost:" + strconv.Itoa(httpPort),
	}

	if cfg.Insecure {
		args = append(args, "--insecure")
	}

	cmd := exec.Command(cfg.Binary, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	// Start the process
	if err := cmd.Start(); err != nil {
		logFile.Close()
		os.RemoveAll(dataDir)
		return nil, fmt.Errorf("failed to start CockroachDB: %w", err)
	}

	testCRDB := &TestCRDB{
		Port:     sqlPort,
		HTTPPort: httpPort,
		DataDir:  dataDir,
		Process:  cmd,
		LogFile:  logFile,
		Binary:   cfg.Binary,
	}

	return testCRDB, nil
}

// Stop stops the CockroachDB instance
func (c *TestCRDB) Stop() error {
	if c.Process != nil && c.Process.Process != nil {
		// Try graceful shutdown first
		if err := c.Process.Process.Signal(os.Interrupt); err != nil {
			// Force kill if graceful shutdown fails
			c.Process.Process.Kill()
		}

		// Wait for process to exit
		c.Process.Wait()
	}

	if c.LogFile != nil {
		c.LogFile.Close()
	}

	if c.DataDir != "" {
		os.RemoveAll(c.DataDir)
	}

	return nil
}

// Reset clears all data in the database (for reuse between tests)
func (c *TestCRDB) Reset() error {
	db, err := c.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect for reset: %w", err)
	}
	defer db.Close()

	// Drop all user databases and tables
	rows, err := db.Query("SELECT database_name FROM [SHOW DATABASES] WHERE database_name NOT IN ('system', 'postgres', 'defaultdb')")
	if err != nil {
		return fmt.Errorf("failed to list databases: %w", err)
	}
	defer rows.Close()

	var databases []string
	for rows.Next() {
		var dbName string
		if err := rows.Scan(&dbName); err != nil {
			return fmt.Errorf("failed to scan database name: %w", err)
		}
		databases = append(databases, dbName)
	}

	// Drop each database
	for _, dbName := range databases {
		_, err := db.Exec(fmt.Sprintf("DROP DATABASE %s CASCADE", dbName))
		if err != nil {
			return fmt.Errorf("failed to drop database %s: %w", dbName, err)
		}
	}

	return nil
}

// Connect creates a database connection to the test instance
func (c *TestCRDB) Connect() (*sql.DB, error) {
	return c.ConnectToDatabase("defaultdb")
}

// ConnectToDatabase creates a database connection to a specific database
func (c *TestCRDB) ConnectToDatabase(dbName string) (*sql.DB, error) {
	connStr := fmt.Sprintf("postgresql://root@localhost:%d/%s?sslmode=disable", c.Port, dbName)
	return sql.Open("postgres", connStr)
}

// GetConnectionString returns the connection string for the test instance
func (c *TestCRDB) GetConnectionString(dbName string) string {
	return fmt.Sprintf("postgresql://root@localhost:%d/%s?sslmode=disable", c.Port, dbName)
}

// GetAddr returns the address of the SQL server
func (c *TestCRDB) GetAddr() string {
	return fmt.Sprintf("localhost:%d", c.Port)
}

// GetHTTPAddr returns the address of the HTTP server
func (c *TestCRDB) GetHTTPAddr() string {
	return fmt.Sprintf("localhost:%d", c.HTTPPort)
}

// GetLogs returns the contents of the log file
func (c *TestCRDB) GetLogs() (string, error) {
	if c.LogFile == nil {
		return "", fmt.Errorf("no log file")
	}

	// Seek to beginning
	c.LogFile.Seek(0, 0)

	// Read all content
	content, err := io.ReadAll(c.LogFile)
	if err != nil {
		return "", fmt.Errorf("failed to read logs: %w", err)
	}

	return string(content), nil
}

// WaitForCRDB waits for CockroachDB to be ready
func WaitForCRDB(crdb *TestCRDB, timeout int) error {
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)

	for time.Now().Before(deadline) {
		// Try to connect
		db, err := crdb.Connect()
		if err == nil {
			// Try a simple query
			var version string
			err = db.QueryRow("SELECT version()").Scan(&version)
			db.Close()

			if err == nil {
				return nil
			}
		}

		time.Sleep(500 * time.Millisecond)
	}

	// Get logs for debugging
	logs, _ := crdb.GetLogs()
	return fmt.Errorf("CockroachDB did not become ready within %d seconds. Last logs:\n%s", timeout, logs)
}

// CreateDatabase creates a new database
func (c *TestCRDB) CreateDatabase(name string) error {
	db, err := c.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer db.Close()

	_, err = db.Exec(fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", name))
	if err != nil {
		return fmt.Errorf("failed to create database: %w", err)
	}

	return nil
}

// CreateUser creates a new user
func (c *TestCRDB) CreateUser(username, password string) error {
	db, err := c.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer db.Close()

	// Create user
	_, err = db.Exec(fmt.Sprintf("CREATE USER IF NOT EXISTS %s WITH PASSWORD '%s'", username, password))
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// GrantAccess grants access to a user on a database
func (c *TestCRDB) GrantAccess(username, database string) error {
	db, err := c.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer db.Close()

	// Grant all privileges
	_, err = db.Exec(fmt.Sprintf("GRANT ALL ON DATABASE %s TO %s", database, username))
	if err != nil {
		return fmt.Errorf("failed to grant access: %w", err)
	}

	return nil
}

// ExecuteSQL executes arbitrary SQL
func (c *TestCRDB) ExecuteSQL(query string, args ...interface{}) error {
	db, err := c.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer db.Close()

	_, err = db.Exec(query, args...)
	return err
}

// Helper function to find an available port
func findAvailablePort() (int, error) {
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	return addr.Port, nil
}

// IsCockroachInstalled checks if the cockroach binary is available
func IsCockroachInstalled() bool {
	// Check for local binary first
	if _, err := os.Stat("../../cockroach"); err == nil {
		return true
	}
	if _, err := os.Stat("./cockroach"); err == nil {
		return true
	}
	// Check in PATH
	_, err := exec.LookPath("cockroach")
	return err == nil
}

// GetCockroachVersion returns the version of the cockroach binary
func GetCockroachVersion() (string, error) {
	cmd := exec.Command("cockroach", "version")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// Parse version from output
	lines := strings.Split(string(output), "\n")
	if len(lines) > 0 {
		return strings.TrimSpace(lines[0]), nil
	}

	return "", fmt.Errorf("failed to parse version")
}
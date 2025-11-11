package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cockroachdb/attested-tls-proxy-cockroach/internal/config"
	"github.com/cockroachdb/attested-tls-proxy-cockroach/internal/logger"
	"github.com/cockroachdb/attested-tls-proxy-cockroach/pkg/api"
	"github.com/cockroachdb/attested-tls-proxy-cockroach/pkg/backend"
)

func main() {
	// Parse command-line flags
	configPath := flag.String("config", "config/dev.yaml", "Path to configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	if err := logger.Init(cfg.Logging.Level, cfg.Logging.AuditFile); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	logger.Log.Info().
		Str("version", "0.1.0").
		Msg("Attested TLS Proxy starting")

	// Create proxy
	proxy, err := backend.NewProxy(cfg)
	if err != nil {
		logger.Log.Fatal().
			Err(err).
			Msg("Failed to create proxy")
	}

	// Start HTTP API server if enabled
	if cfg.Proxy.API.Enabled && proxy.GetAttestationStore() != nil {
		apiServer := api.NewServer(proxy.GetAttestationStore(), cfg.Proxy.NodeID)
		go func() {
			logger.Log.Info().
				Str("address", cfg.Proxy.API.Listen).
				Msg("Starting HTTP API server")
			if err := apiServer.Start(cfg.Proxy.API.Listen); err != nil {
				logger.Log.Error().
					Err(err).
					Msg("HTTP API server failed")
			}
		}()
	}

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start proxy in goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := proxy.Start(); err != nil {
			errChan <- err
		}
	}()

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		logger.Log.Info().
			Str("signal", sig.String()).
			Msg("Received shutdown signal")
	case err := <-errChan:
		logger.Log.Error().
			Err(err).
			Msg("Proxy error")
	}

	// Graceful shutdown
	logger.Info("Initiating graceful shutdown...")
	proxy.Stop()
	proxy.WaitForConnections()

	logger.Info("Proxy stopped successfully")
}
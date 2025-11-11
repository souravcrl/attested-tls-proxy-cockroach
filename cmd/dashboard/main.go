package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cockroachdb/attested-tls-proxy-cockroach/internal/logger"
	"github.com/cockroachdb/attested-tls-proxy-cockroach/pkg/attestation"
)

// ProxyNode represents a proxy node in the cluster
type ProxyNode struct {
	ID      string `yaml:"id" json:"id"`
	Address string `yaml:"address" json:"address"`
	Healthy bool   `json:"healthy"`
}

// AggregatedData holds aggregated attestation data from all proxies
type AggregatedData struct {
	TotalClients        int                              `json:"total_clients"`
	ActiveClients       int                              `json:"active_clients"`
	AttestationsByProxy map[string]int                   `json:"attestations_by_proxy"`
	MeasurementStats    map[string]int                   `json:"measurement_stats"`
	Clients             []ClientAttestationWithProxy     `json:"clients"`
	ProxyNodes          []ProxyNode                      `json:"proxy_nodes"`
	LastUpdated         time.Time                        `json:"last_updated"`
}

// ClientAttestationWithProxy extends client attestation with proxy address
type ClientAttestationWithProxy struct {
	*attestation.ClientAttestation
	ProxyAddress string `json:"proxy_address"`
}

// Dashboard manages the centralized attestation dashboard
type Dashboard struct {
	config      *DashboardConfig
	cache       *AggregatedData
	cacheMutex  sync.RWMutex
	httpClient  *http.Client
}

// DashboardConfig holds dashboard configuration
type DashboardConfig struct {
	Listen          string      `yaml:"listen"`
	RefreshInterval string      `yaml:"refresh_interval"`
	ProxyNodes      []ProxyNode `yaml:"proxy_nodes"`
}

// NewDashboard creates a new dashboard instance
func NewDashboard(config *DashboardConfig) *Dashboard {
	return &Dashboard{
		config: config,
		cache: &AggregatedData{
			AttestationsByProxy: make(map[string]int),
			MeasurementStats:    make(map[string]int),
			Clients:             []ClientAttestationWithProxy{},
			ProxyNodes:          config.ProxyNodes,
		},
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Start starts the dashboard server and background refresh loop
func (d *Dashboard) Start() error {
	// Parse refresh interval
	refreshInterval, err := time.ParseDuration(d.config.RefreshInterval)
	if err != nil {
		refreshInterval = 10 * time.Second
	}

	// Start background refresh loop
	go d.refreshLoop(refreshInterval)

	// Register HTTP handlers
	http.HandleFunc("/", d.handleIndex)
	http.HandleFunc("/api/aggregated", d.handleAggregated)
	http.HandleFunc("/api/topology", d.handleTopology)
	http.HandleFunc("/api/health", d.handleHealth)

	logger.Log.Info().
		Str("address", d.config.Listen).
		Int("proxy_nodes", len(d.config.ProxyNodes)).
		Str("refresh_interval", refreshInterval.String()).
		Msg("Starting attestation dashboard")

	return http.ListenAndServe(d.config.Listen, nil)
}

// refreshLoop periodically refreshes data from all proxy nodes
func (d *Dashboard) refreshLoop(interval time.Duration) {
	// Initial refresh
	d.refreshData()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		d.refreshData()
	}
}

// refreshData queries all proxy nodes and aggregates data
func (d *Dashboard) refreshData() {
	logger.Log.Debug().Msg("Refreshing attestation data from all proxies")

	var wg sync.WaitGroup
	var mutex sync.Mutex

	aggregated := &AggregatedData{
		AttestationsByProxy: make(map[string]int),
		MeasurementStats:    make(map[string]int),
		Clients:             []ClientAttestationWithProxy{},
		ProxyNodes:          d.config.ProxyNodes,
		LastUpdated:         time.Now(),
	}

	// Query all proxy nodes in parallel
	for i := range d.config.ProxyNodes {
		wg.Add(1)
		go func(node *ProxyNode) {
			defer wg.Done()

			// Query attestations from this proxy
			url := fmt.Sprintf("http://%s/api/v1/attestations?limit=100", node.Address)
			resp, err := d.httpClient.Get(url)
			if err != nil {
				logger.Log.Warn().
					Err(err).
					Str("node_id", node.ID).
					Str("address", node.Address).
					Msg("Failed to query proxy node")
				mutex.Lock()
				node.Healthy = false
				mutex.Unlock()
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				logger.Log.Warn().
					Str("node_id", node.ID).
					Int("status_code", resp.StatusCode).
					Msg("Proxy node returned non-OK status")
				mutex.Lock()
				node.Healthy = false
				mutex.Unlock()
				return
			}

			var result struct {
				ProxyNodeID  string                           `json:"proxy_node_id"`
				Count        int                              `json:"count"`
				Attestations []*attestation.ClientAttestation `json:"attestations"`
			}

			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				logger.Log.Warn().
					Err(err).
					Str("node_id", node.ID).
					Msg("Failed to decode response from proxy")
				mutex.Lock()
				node.Healthy = false
				mutex.Unlock()
				return
			}

			// Mark node as healthy
			mutex.Lock()
			node.Healthy = true

			// Aggregate data
			aggregated.AttestationsByProxy[node.ID] = result.Count
			aggregated.TotalClients += result.Count

			// Count active connections (those without disconnected_at)
			activeCount := 0
			if result.Attestations != nil {
				for _, client := range result.Attestations {
					if client != nil && !client.DisconnectedAt.IsZero() {
						// DisconnectedAt is NOT zero means it's disconnected
						// We want to count connections where DisconnectedAt IS zero (not yet disconnected)
					} else if client != nil {
						activeCount++
					}
				}
			}
			aggregated.ActiveClients += activeCount

			// Process attestations
			if result.Attestations != nil {
				for _, client := range result.Attestations {
					if client == nil {
						continue
					}

					// Create safe copy to avoid potential race conditions
					clientCopy := *client
					aggregated.Clients = append(aggregated.Clients, ClientAttestationWithProxy{
						ClientAttestation: &clientCopy,
						ProxyAddress:      node.Address,
					})

					// Aggregate measurement stats
					if count, ok := aggregated.MeasurementStats[clientCopy.Measurement]; ok {
						aggregated.MeasurementStats[clientCopy.Measurement] = count + 1
					} else {
						aggregated.MeasurementStats[clientCopy.Measurement] = 1
					}
				}
			}
			mutex.Unlock()
		}(&d.config.ProxyNodes[i])
	}

	wg.Wait()

	// Update cache
	d.cacheMutex.Lock()
	d.cache = aggregated
	d.cacheMutex.Unlock()

	logger.Log.Debug().
		Int("total_clients", aggregated.TotalClients).
		Int("active_clients", aggregated.ActiveClients).
		Int("unique_measurements", len(aggregated.MeasurementStats)).
		Msg("Attestation data refreshed")
}

// handleAggregated returns aggregated data as JSON
func (d *Dashboard) handleAggregated(w http.ResponseWriter, r *http.Request) {
	d.cacheMutex.RLock()
	data := d.cache
	d.cacheMutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// handleTopology returns cluster topology
func (d *Dashboard) handleTopology(w http.ResponseWriter, r *http.Request) {
	d.cacheMutex.RLock()
	defer d.cacheMutex.RUnlock()

	topology := map[string]interface{}{
		"nodes":   d.cache.ProxyNodes,
		"clients": d.cache.Clients,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(topology)
}

// handleHealth returns dashboard health status
func (d *Dashboard) handleHealth(w http.ResponseWriter, r *http.Request) {
	d.cacheMutex.RLock()
	healthyNodes := 0
	for _, node := range d.cache.ProxyNodes {
		if node.Healthy {
			healthyNodes++
		}
	}
	d.cacheMutex.RUnlock()

	status := "healthy"
	if healthyNodes == 0 {
		status = "unhealthy"
	} else if healthyNodes < len(d.cache.ProxyNodes) {
		status = "degraded"
	}

	response := map[string]interface{}{
		"status":        status,
		"total_nodes":   len(d.cache.ProxyNodes),
		"healthy_nodes": healthyNodes,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleIndex serves the HTML dashboard
func (d *Dashboard) handleIndex(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html>
<head>
    <title>Attestation Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .header {
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 { margin: 0; color: #333; }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .stat-card h3 { margin: 0 0 10px 0; color: #666; font-size: 14px; }
        .stat-card .value { font-size: 2.5em; font-weight: bold; color: #2c3e50; }
        .charts-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }
        .chart-container {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            max-height: 350px;
        }
        .chart-container canvas {
            max-height: 250px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }
        th {
            background-color: #2c3e50;
            color: white;
            font-weight: 600;
        }
        tr:hover { background-color: #f8f9fa; }
        .allowed { color: #27ae60; font-weight: 600; }
        .denied { color: #e74c3c; font-weight: 600; }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }
        .badge-success { background-color: #d4edda; color: #155724; }
        .badge-danger { background-color: #f8d7da; color: #721c24; }
        .last-updated {
            color: #666;
            font-size: 12px;
            margin-top: 10px;
        }
        .pagination {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 10px;
            margin-top: 20px;
            padding: 20px;
        }
        .pagination button {
            padding: 8px 16px;
            background-color: #2c3e50;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
        }
        .pagination button:hover:not(:disabled) {
            background-color: #34495e;
        }
        .pagination button:disabled {
            background-color: #95a5a6;
            cursor: not-allowed;
        }
        .pagination span {
            color: #666;
            font-size: 14px;
        }
        .table-container {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Cluster Attestation Dashboard</h1>
        <div class="last-updated" id="lastUpdated">Loading...</div>
    </div>

    <div class="stats">
        <div class="stat-card">
            <h3>Total Clients</h3>
            <div class="value" id="totalClients">-</div>
        </div>
        <div class="stat-card">
            <h3>Active Connections</h3>
            <div class="value" id="activeClients">-</div>
        </div>
        <div class="stat-card">
            <h3>Proxy Nodes</h3>
            <div class="value" id="proxyNodes">-</div>
        </div>
        <div class="stat-card">
            <h3>Unique Measurements</h3>
            <div class="value" id="uniqueMeasurements">-</div>
        </div>
    </div>

    <div class="charts-grid">
        <div class="chart-container">
            <h2 style="margin-top: 0; font-size: 18px;">Clients by Measurement</h2>
            <canvas id="measurementChart"></canvas>
        </div>

        <div class="chart-container">
            <h2 style="margin-top: 0; font-size: 18px;">Clients by Proxy Node</h2>
            <canvas id="proxyChart"></canvas>
        </div>
    </div>

    <h2 style="margin-left: 0;">Attestation Records</h2>
    <div class="table-container">
        <table id="clientsTable">
            <thead>
                <tr>
                    <th>Client ID</th>
                    <th>Measurement</th>
                    <th>TCB Version</th>
                    <th>Debug</th>
                    <th>SMT</th>
                    <th>Connected At</th>
                    <th>Proxy Node</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody></tbody>
        </table>
        <div class="pagination">
            <button id="prevPage">← Previous</button>
            <span id="pageInfo">Page 1 of 1</span>
            <button id="nextPage">Next →</button>
        </div>
    </div>

    <script>
        let measurementChart = null;
        let proxyChart = null;
        let allClients = [];
        let currentPage = 1;
        const itemsPerPage = 10;

        function renderTable() {
            const tbody = document.querySelector('#clientsTable tbody');
            tbody.innerHTML = '';

            const startIndex = (currentPage - 1) * itemsPerPage;
            const endIndex = startIndex + itemsPerPage;
            const pageClients = allClients.slice(startIndex, endIndex);

            if (pageClients.length > 0) {
                pageClients.forEach(client => {
                    const row = tbody.insertRow();
                    row.innerHTML = '<td><code>' + client.client_id + '</code></td>' +
                        '<td><code>' + client.measurement.substring(0, 16) + '...</code></td>' +
                        '<td>' + (client.tcb_version || 'N/A') + '</td>' +
                        '<td>' + (client.debug_enabled ? '<span class="badge badge-danger">Yes</span>' : '<span class="badge badge-success">No</span>') + '</td>' +
                        '<td>' + (client.smt_enabled ? '<span class="badge badge-danger">Yes</span>' : '<span class="badge badge-success">No</span>') + '</td>' +
                        '<td>' + new Date(client.connected_at).toLocaleString() + '</td>' +
                        '<td>' + client.proxy_address + '</td>' +
                        '<td class="' + client.verify_result + '">' + client.verify_result + '</td>';
                });
            } else {
                const row = tbody.insertRow();
                row.innerHTML = '<td colspan="8" style="text-align: center; color: #999;">No attestation records</td>';
            }

            // Update pagination controls
            const totalPages = Math.ceil(allClients.length / itemsPerPage) || 1;
            document.getElementById('pageInfo').textContent = 'Page ' + currentPage + ' of ' + totalPages + ' (' + allClients.length + ' total)';
            document.getElementById('prevPage').disabled = currentPage === 1;
            document.getElementById('nextPage').disabled = currentPage >= totalPages;
        }

        document.getElementById('prevPage').addEventListener('click', () => {
            if (currentPage > 1) {
                currentPage--;
                renderTable();
            }
        });

        document.getElementById('nextPage').addEventListener('click', () => {
            const totalPages = Math.ceil(allClients.length / itemsPerPage);
            if (currentPage < totalPages) {
                currentPage++;
                renderTable();
            }
        });

        function updateDashboard() {
            fetch('/api/aggregated')
                .then(r => r.json())
                .then(data => {
                    // Update stats
                    document.getElementById('totalClients').textContent = data.total_clients || 0;
                    document.getElementById('activeClients').textContent = data.active_clients || 0;
                    document.getElementById('proxyNodes').textContent = data.proxy_nodes?.length || 0;
                    document.getElementById('uniqueMeasurements').textContent = Object.keys(data.measurement_stats || {}).length;
                    document.getElementById('lastUpdated').textContent =
                        'Last updated: ' + new Date(data.last_updated).toLocaleString();

                    // Update measurement chart
                    const measurements = data.measurement_stats || {};
                    const measurementLabels = Object.keys(measurements).map(m => m.substring(0, 12) + '...');
                    const measurementValues = Object.values(measurements);

                    if (measurementChart) {
                        measurementChart.destroy();
                    }

                    measurementChart = new Chart(document.getElementById('measurementChart'), {
                        type: 'bar',
                        data: {
                            labels: measurementLabels,
                            datasets: [{
                                label: 'Clients',
                                data: measurementValues,
                                backgroundColor: 'rgba(52, 152, 219, 0.6)',
                                borderColor: 'rgba(52, 152, 219, 1)',
                                borderWidth: 1
                            }]
                        },
                        options: {
                            responsive: true,
                            scales: {
                                y: {
                                    beginAtZero: true,
                                    ticks: { precision: 0 }
                                }
                            }
                        }
                    });

                    // Update proxy chart
                    const proxyStats = data.attestations_by_proxy || {};
                    const proxyLabels = Object.keys(proxyStats);
                    const proxyValues = Object.values(proxyStats);

                    if (proxyChart) {
                        proxyChart.destroy();
                    }

                    proxyChart = new Chart(document.getElementById('proxyChart'), {
                        type: 'doughnut',
                        data: {
                            labels: proxyLabels,
                            datasets: [{
                                data: proxyValues,
                                backgroundColor: [
                                    'rgba(52, 152, 219, 0.6)',
                                    'rgba(46, 204, 113, 0.6)',
                                    'rgba(155, 89, 182, 0.6)',
                                    'rgba(241, 196, 15, 0.6)',
                                    'rgba(231, 76, 60, 0.6)'
                                ]
                            }]
                        },
                        options: {
                            responsive: true
                        }
                    });

                    // Update clients table with pagination
                    allClients = data.clients || [];
                    renderTable();
                })
                .catch(err => {
                    console.error('Failed to fetch data:', err);
                    document.getElementById('lastUpdated').textContent = 'Error loading data';
                });
        }

        // Initial update
        updateDashboard();

        // Refresh every 10 seconds
        setInterval(updateDashboard, 10000);
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// loadConfig loads configuration from YAML file
func loadConfig(path string) (*DashboardConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	config := &DashboardConfig{}
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Set defaults
	if config.Listen == "" {
		config.Listen = ":9090"
	}
	if config.RefreshInterval == "" {
		config.RefreshInterval = "10s"
	}

	return config, nil
}

func main() {
	configPath := flag.String("config", "config/dashboard.yaml", "Path to dashboard configuration file")
	flag.Parse()

	// Initialize logger
	logger.Init("info", "")

	// Load configuration
	config, err := loadConfig(*configPath)
	if err != nil {
		logger.Log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	// Create and start dashboard
	dashboard := NewDashboard(config)
	if err := dashboard.Start(); err != nil {
		logger.Log.Fatal().Err(err).Msg("Dashboard server failed")
	}
}
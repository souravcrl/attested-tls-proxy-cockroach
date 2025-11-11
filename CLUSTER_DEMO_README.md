# Attested TLS Proxy Cluster Demo - RUNNING NOW! 🎉

## 🚀 Your Cluster is Live!

### Dashboard Access
**🔗 Main Dashboard:** [http://localhost:9090](http://localhost:9090)

Open this link in your browser to see the real-time attestation monitoring dashboard with:
- Live statistics across all 3 proxy nodes
- Client distribution charts
- Measurement visualization
- Active connection tracking

---

## 📊 Cluster Architecture

Your running cluster consists of:

### CockroachDB Nodes (3 nodes)
- **Node 1**: `localhost:26258` → [Admin UI](http://localhost:8091)
- **Node 2**: `localhost:26268` → [Admin UI](http://localhost:8092)
- **Node 3**: `localhost:26278` → [Admin UI](http://localhost:8093)

### Attested TLS Proxy Nodes (3 proxies)
- **Proxy 1**: `localhost:26257` → CRDB `localhost:26258`
  - API: [http://localhost:8081/api/v1/stats/overview](http://localhost:8081/api/v1/stats/overview)
  - Health: [http://localhost:8081/api/v1/health](http://localhost:8081/api/v1/health)

- **Proxy 2**: `localhost:26267` → CRDB `localhost:26268`
  - API: [http://localhost:8082/api/v1/stats/overview](http://localhost:8082/api/v1/stats/overview)
  - Health: [http://localhost:8082/api/v1/health](http://localhost:8082/api/v1/health)

- **Proxy 3**: `localhost:26277` → CRDB `localhost:26278`
  - API: [http://localhost:8083/api/v1/stats/overview](http://localhost:8083/api/v1/stats/overview)
  - Health: [http://localhost:8083/api/v1/health](http://localhost:8083/api/v1/health)

---

## 🔍 API Endpoints Available

### Per-Proxy Endpoints
Each proxy exposes these endpoints on ports 8081, 8082, 8083:

```bash
# Overall statistics
curl http://localhost:8081/api/v1/stats/overview | jq

# Active clients
curl http://localhost:8081/api/v1/clients/active | jq

# Recent attestations
curl http://localhost:8081/api/v1/attestations?limit=10 | jq

# Health check
curl http://localhost:8081/api/v1/health | jq

# Node information
curl http://localhost:8081/api/v1/node/info | jq

# Statistics by measurement
curl http://localhost:8081/api/v1/stats/measurements | jq
```

### Dashboard Endpoint
```bash
# Aggregated cluster data
curl http://localhost:9090/api/aggregated | jq

# Cluster topology
curl http://localhost:9090/api/topology | jq
```

---

## 🧪 Testing with Attested Clients

### Run the Integration Tests
The existing integration tests create attested TLS connections:

```bash
cd tests/integration
export CGO_CFLAGS="-I/opt/homebrew/Cellar/openssl@3/3.5.0/include"
export CGO_LDFLAGS="-L/opt/homebrew/Cellar/openssl@3/3.5.0/lib -lcrypto"

# Run 5 test iterations (creates 5 attestation records)
go test -v -run TestValidAttestation -count=5

# Test multiple concurrent connections
go test -v -run TestE2EMultipleConnections
```

After running tests, check the dashboard to see:
- Attestation records created
- Client distribution across proxies
- Connection statistics

---

## 📁 Log Files

View detailed logs at:
- **Proxy 1**: `/tmp/proxy1.log`
- **Proxy 2**: `/tmp/proxy2.log`
- **Proxy 3**: `/tmp/proxy3.log`
- **Dashboard**: `/tmp/dashboard.log`

Example:
```bash
# Watch proxy 1 logs in real-time
tail -f /tmp/proxy1.log

# Check for attestation records
grep "Attestation" /tmp/proxy*.log
```

---

## 🗄️ Attestation Database

Each proxy stores attestation data locally in SQLite:
- **Proxy 1**: `/tmp/attestations-node1.db`
- **Proxy 2**: `/tmp/attestations-node2.db`
- **Proxy 3**: `/tmp/attestations-node3.db`

Query directly:
```bash
sqlite3 /tmp/attestations-node1.db "SELECT * FROM client_attestations;"
```

---

## 🎯 What's Running?

### Attestation Features Active:
✅ **Simulated SEV-SNP Attestation** - Full attestation workflow without hardware
✅ **Policy Verification** - Validates measurement, TCB version, debug/SMT flags
✅ **SQLite Storage** - Persistent attestation records with indexed queries
✅ **HTTP REST API** - 7 endpoints per proxy for monitoring
✅ **Real-time Dashboard** - Live visualization with Chart.js
✅ **Distributed Architecture** - 3 independent proxies with centralized monitoring
✅ **Connection Tracking** - Bytes in/out, connection lifecycle

---

## 🛑 Stopping the Cluster

The cluster is running in the background. To stop it:

```bash
# The cleanup will happen automatically if you press Ctrl+C on the script
# Or manually stop processes:
pkill -f "cockroach start"
pkill -f "attested-tls-proxy"
pkill -f "dashboard"
```

---

## 🔄 Restarting the Cluster

Simply run the demo script again:
```bash
./run-cluster-demo.sh
```

It will automatically:
1. Clean up any existing processes
2. Start 3 CockroachDB nodes
3. Initialize the cluster
4. Start 3 attested TLS proxies
5. Start the centralized dashboard
6. Run test clients

---

## 📊 Dashboard Features

Open [http://localhost:9090](http://localhost:9090) to see:

### Real-time Statistics Cards
- **Total Clients**: Number of unique clients across all proxies
- **Active Connections**: Currently connected clients
- **Proxy Nodes**: Number of healthy proxies (3/3)
- **Unique Measurements**: Different VM/app versions

### Visualizations
- **Bar Chart**: Client distribution by measurement hash
- **Doughnut Chart**: Client distribution by proxy node
- **Client Table**: Detailed view with:
  - Client ID (derived from measurement)
  - Measurement hash (first 16 chars)
  - TCB version
  - Debug enabled status (color-coded badge)
  - SMT enabled status (color-coded badge)
  - Connection timestamp
  - Proxy address
  - Verification result (allowed/denied)

### Auto-Refresh
- Dashboard updates every 5 seconds
- Queries all 3 proxies in parallel
- Aggregates data in real-time

---

## 🎓 Learning Resources

### Configuration Files Used
- `config/proxy-node1.yaml` - Proxy 1 configuration
- `config/proxy-node2.yaml` - Proxy 2 configuration
- `config/proxy-node3.yaml` - Proxy 3 configuration
- `config/dashboard-cluster.yaml` - Dashboard configuration
- `config/attestation-policy.yaml` - Attestation policy rules

### Key Implementation Files
- `pkg/attestation/store.go` - SQLite storage implementation
- `pkg/api/http_server.go` - HTTP API server
- `cmd/dashboard/main.go` - Dashboard web UI
- `pkg/backend/proxy.go` - Proxy with attestation integration
- `pkg/attestation/sev_snp.go` - SEV-SNP attestation (simulated mode)
- `pkg/policy/verifier.go` - Policy verification engine

---

## 💡 Next Steps

1. **View the Dashboard**: Open [http://localhost:9090](http://localhost:9090)

2. **Run Test Clients**: Generate attestation records
   ```bash
   cd tests/integration
   go test -v -run TestValidAttestation -count=10
   ```

3. **Monitor Real-time**: Watch the dashboard update as tests run

4. **Explore the API**: Query individual proxy endpoints

5. **Check Logs**: See detailed attestation verification

6. **Experiment**: Try modifying policy files and restarting proxies

---

## 🎉 Success!

You now have a **fully functional 3-node CockroachDB cluster** with:
- ✅ Attested TLS protection on each node
- ✅ Centralized monitoring dashboard
- ✅ RESTful HTTP APIs for programmatic access
- ✅ SQLite storage for attestation history
- ✅ Real-time visualization
- ✅ Policy-based access control

All running locally without needing SEV-SNP hardware!

---

**Generated**: 2025-11-12
**Cluster Status**: 🟢 RUNNING
**Dashboard**: http://localhost:9090

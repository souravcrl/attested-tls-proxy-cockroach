# Attested TLS Proxy for CockroachDB

A Trusted Execution Environment (TEE)-based proxy that enhances TLS 1.3 with hardware-rooted attestation for CockroachDB connections. This proxy ensures **what is running**, not just **who is connecting**, using IETF RATS-compliant attestation and OAuth Token Exchange.

## Overview

Traditional TLS proves *identity* via certificates. Attested TLS (aTLS) adds *integrity* by having a TEE-hosted proxy present hardware-rooted evidence during the handshake. This allows clients and Identity Providers to verify the exact software running in the proxy before granting access.

### Key Features

- **Hardware-Rooted Attestation**: TEE (AMD SEV-SNP) generates cryptographic evidence of running code
- **IETF RATS Compliance**: Entity Attestation Tokens (EAT) follow standardized attestation models
- **Short-Lived Credentials**: OAuth Token Exchange issues time-limited, sender-constrained tokens
- **Exported Authenticators**: TLS 1.3 extension binds attestation results to session keys
- **Nonce Binding**: Fresh attestation per request prevents replay attacks
- **Zero Backend Changes**: Transparent proxy - CockroachDB requires no modifications
- **Policy Enforcement**: Configurable measurement verification and access control

### Use Cases

- AI inference gateways requiring code provenance
- Database front-ends with strict compliance requirements
- Multi-tenant environments needing cryptographic isolation guarantees
- Zero-trust architectures with hardware-based trust anchors

## Architecture

```
┌─────────┐    aTLS+Auth    ┌──────────────┐   Standard TLS   ┌──────────────┐
│ Client  │ ───────────────>│  TEE Proxy   │ ───────────────> │  CockroachDB │
│         │ <───────────────│  (SEV-SNP)   │ <─────────────── │   Backend    │
└─────────┘                 └──────────────┘                  └──────────────┘
     │                             │
     │                             │
     ▼                             ▼
┌─────────┐                 ┌──────────────┐
│Verifier │                 │     STS      │
│Service  │                 │ (Token Svc)  │
└─────────┘                 └──────────────┘
(Veraison/Azure/GCP)        (OAuth Token Exchange)
```

### Flow

1. **Handshake**: Client initiates TLS 1.3 connection to proxy
2. **Attestation**: Proxy presents TEE attestation evidence (EAT) via Exported Authenticators
3. **Verification**: Client or IdP verifies evidence against policy (measurements, TCB version, etc.)
4. **Token Exchange**: STS issues short-lived DPoP/JWT bound to session
5. **Request Processing**: Proxy validates fresh nonce-bound attestation on each request
6. **Backend Forwarding**: Only compliant requests forwarded to CockroachDB
7. **Audit**: All decisions logged for compliance

## Project Structure

```
.
├── proxy/              # TEE proxy implementation (Rust/Go)
│   ├── attestation/    # EAT generation and nonce binding
│   ├── tls/            # Exported Authenticators integration
│   ├── policy/         # Measurement and policy enforcement
│   └── backend/        # CockroachDB connection handling
├── verifier/           # Integration with attestation verifiers
│   ├── veraison/       # Veraison verifier client
│   ├── azure/          # Azure Attestation integration
│   └── gcp/            # GCP Confidential Computing verification
├── sts/                # Security Token Service
│   ├── oauth/          # OAuth Token Exchange implementation
│   └── dpop/           # DPoP token binding
├── backend/            # Backend integrations
│   ├── cockroachdb/    # CRDB-specific handling
│   ├── postgres/       # PostgreSQL support
│   └── inference/      # AI inference gateway support
├── config/             # Configuration and policy files
├── iac/                # Infrastructure as Code
│   ├── terraform/      # Terraform configurations
│   └── gcloud/         # GCP-specific deployment scripts
├── tests/              # Integration and CI tests
│   ├── measurement/    # Measurement drift simulation
│   └── e2e/            # End-to-end scenarios
└── docs/               # Additional documentation
```

## Deliverables

### Phase 1: Core Proxy
- [x] TEE proxy implementation (Rust/Go)
- [x] Exported Authenticators support
- [x] Nonce generation and binding
- [x] Policy engine for measurement verification
- [ ] CockroachDB backend integration

### Phase 2: Attestation & Verification
- [ ] Veraison verifier integration
- [ ] Azure Attestation support
- [ ] GCP Confidential Computing verification
- [ ] STS with OAuth Token Exchange
- [ ] DPoP/JWT token generation

### Phase 3: Production Features
- [ ] HBA (Host-Based Authentication) integration
- [ ] IP allowlist enforcement
- [ ] Comprehensive audit logging
- [ ] Failure mode handling and circuit breakers
- [ ] PostgreSQL backend support (optional)
- [ ] AI inference gateway support (optional)

### Phase 4: Operations
- [ ] IaC templates (Terraform/Pulumi)
- [ ] CI/CD pipeline with automated tests
- [ ] Measurement drift simulation and detection
- [ ] Automated rollback on policy violations
- [ ] Monitoring and alerting integration

## Deployment

### GCP Confidential VM (AMD SEV-SNP)

The proxy runs in a GCP Confidential VM with AMD SEV-SNP for hardware-rooted attestation.

#### Prerequisites

- GCP project with Confidential Computing API enabled
- `gcloud` CLI configured
- AMD Milan CPU platform (for SEV-SNP)

#### Create Confidential VM

```bash
gcloud compute instances create cockroachdb-atls-proxy \
  --machine-type=n2d-standard-2 \
  --min-cpu-platform="AMD Milan" \
  --zone=us-central1-a \
  --confidential-compute-type=SEV_SNP \
  --maintenance-policy=TERMINATE \
  --image-project=ubuntu-os-cloud \
  --image-family=ubuntu-2404-lts-amd64 \
  --boot-disk-size=20GB \
  --tags=atls-proxy,cockroachdb-client
```

#### Deploy Proxy

```bash
# SSH into the VM
gcloud compute ssh cockroachdb-atls-proxy --zone=us-central1-a

# Install dependencies (example for Go-based proxy)
sudo apt-get update
sudo apt-get install -y golang-go build-essential

# Clone and build proxy
git clone <repository-url>
cd attested-tls-proxy-cockroach
make build

# Configure proxy
cp config/proxy.example.yaml config/proxy.yaml
# Edit config/proxy.yaml with your settings

# Start proxy
./bin/atls-proxy --config config/proxy.yaml
```

### Configuration Example

```yaml
# config/proxy.yaml
proxy:
  listen: "0.0.0.0:26257"  # CockroachDB default port
  backend:
    host: "cockroachdb.internal"
    port: 26257
    tls:
      enabled: true
      ca_cert: "/path/to/ca.crt"

attestation:
  provider: "gcp"  # gcp, azure, or veraison
  policy:
    measurements:
      - name: "kernel"
        hash: "sha384:abcd1234..."
      - name: "application"
        hash: "sha384:efgh5678..."
    tcb_version_min: "1.0"
  nonce_ttl: 300s  # 5 minutes

tokens:
  sts_url: "https://sts.example.com/token"
  token_ttl: 3600s  # 1 hour
  dpop_enabled: true

logging:
  level: "info"
  audit_file: "/var/log/atls-proxy/audit.json"

policy:
  require_fresh_attestation: true
  max_attestation_age: 60s
```

## Security Considerations

### Threat Model

**In Scope:**
- Compromised client attempting unauthorized access
- Man-in-the-middle attacks on proxy-backend connection
- Replay attacks using stale attestation
- Measurement drift (unauthorized code changes)

**Out of Scope:**
- Physical attacks on TEE hardware
- Supply chain attacks on TEE firmware (assumed trusted)
- Side-channel attacks (mitigated by SEV-SNP)

### Trust Assumptions

1. **Hardware Root of Trust**: AMD SEV-SNP provides valid attestation
2. **Verifier Integrity**: Attestation verifier service is trusted
3. **STS Security**: Token service properly validates attestation results
4. **Policy Correctness**: Measurement policies accurately reflect authorized code

### Best Practices

- Rotate nonces on every request
- Use short-lived tokens (≤1 hour)
- Monitor measurement drift continuously
- Implement circuit breakers for verifier failures
- Log all attestation decisions for audit
- Regularly update TCB baseline measurements

## Development

### Build

```bash
# Go-based proxy
make build

# Run tests
make test

# Run with race detector
make test-race
```

### Testing

```bash
# Unit tests
make test-unit

# Integration tests (requires running verifier)
make test-integration

# Measurement drift simulation
make test-drift

# End-to-end tests (requires full stack)
make test-e2e
```

### Local Development

For local development without a TEE, you can use simulated attestation:

```yaml
# config/proxy.dev.yaml
attestation:
  provider: "simulated"  # Only for development!
  policy:
    enforce: false
```

**WARNING**: Never use simulated attestation in production!

## Monitoring

### Key Metrics

- `atls_attestation_verifications_total` - Total attestation verifications
- `atls_attestation_failures_total` - Failed attestation attempts
- `atls_policy_violations_total` - Policy enforcement denials
- `atls_token_issues_total` - STS token issuances
- `atls_backend_requests_total` - Forwarded backend requests
- `atls_measurement_drift_detected` - Unauthorized code change alerts

### Health Checks

```bash
# Proxy health
curl http://localhost:8080/health

# Attestation readiness
curl http://localhost:8080/attestation/ready

# Metrics
curl http://localhost:8080/metrics
```

## Troubleshooting

### Common Issues

**Attestation verification fails:**
- Verify TEE is properly initialized: `dmesg | grep -i sev`
- Check verifier service connectivity
- Validate measurement hashes in policy

**Token issuance errors:**
- Check STS endpoint configuration
- Verify OAuth Token Exchange flow
- Ensure nonce freshness

**Backend connection refused:**
- Verify CockroachDB connectivity
- Check TLS certificates
- Review firewall rules

## Roadmap

- [ ] AWS Nitro Enclaves support
- [ ] Azure Confidential VMs support
- [ ] Multi-backend connection pooling
- [ ] GraphQL API gateway support
- [ ] Kubernetes operator for orchestration
- [ ] WebAssembly-based policy engine
- [ ] FIDO2 client authentication

## Contributing

Contributions welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[Apache 2.0](LICENSE)

## References

- [IETF RATS Architecture](https://datatracker.ietf.org/doc/html/rfc9334)
- [OAuth Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [TLS Exported Authenticators](https://datatracker.ietf.org/doc/html/rfc9261)
- [DPoP](https://datatracker.ietf.org/doc/html/rfc9449)
- [AMD SEV-SNP](https://www.amd.com/en/developer/sev.html)
- [GCP Confidential Computing](https://cloud.google.com/confidential-computing)
- [CockroachDB Security](https://www.cockroachlabs.com/docs/stable/security-reference)

## Support

For issues and questions:
- GitHub Issues: [repository-url]/issues
- Security issues: security@example.com (PGP key available)

## Acknowledgments

Built with support from the IETF RATS working group and the confidential computing community.
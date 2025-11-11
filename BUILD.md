# Building the Attested TLS Proxy

## Prerequisites

### macOS (Apple Silicon / Intel)

1. **Install Homebrew** (if not already installed):
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```

2. **Install OpenSSL**:
   ```bash
   brew install openssl@3
   ```

3. **Install Go** (version 1.21 or later):
   ```bash
   brew install go
   ```

### Linux (Ubuntu/Debian)

```bash
# Install OpenSSL development libraries
sudo apt-get update
sudo apt-get install libssl-dev

# Install Go (if not already installed)
sudo apt-get install golang-go
```

## Building

### Quick Build (macOS with Homebrew OpenSSL)

```bash
# Set CGo flags to find OpenSSL
export CGO_CFLAGS="-I/opt/homebrew/Cellar/openssl@3/3.5.0/include"
export CGO_LDFLAGS="-L/opt/homebrew/Cellar/openssl@3/3.5.0/lib -lcrypto"

# Build the proxy
make build
```

### Generic Build (works on any platform)

```bash
# Find your OpenSSL installation
openssl version -d

# Set CGo flags (adjust paths as needed)
export CGO_CFLAGS="-I/path/to/openssl/include"
export CGO_LDFLAGS="-L/path/to/openssl/lib -lcrypto"

# Build
make build
```

### Build Output

The compiled binary will be at: `bin/atls-proxy`

## Troubleshooting

### Error: `library 'crypto' not found`

This means Go can't find the OpenSSL crypto library. Set the CGo environment variables:

```bash
# macOS (Homebrew)
export CGO_LDFLAGS="-L/opt/homebrew/lib -lcrypto"

# Linux
export CGO_LDFLAGS="-L/usr/lib/x86_64-linux-gnu -lcrypto"
```

### Error: `openssl/crypto.h: No such file or directory`

This means the OpenSSL headers aren't found:

```bash
# macOS (Homebrew)
export CGO_CFLAGS="-I/opt/homebrew/include"

# Linux
export CGO_CFLAGS="-I/usr/include"
```

### Making it Permanent

Add these to your `~/.zshrc` (macOS) or `~/.bashrc` (Linux):

```bash
# For macOS with Homebrew OpenSSL
export CGO_CFLAGS="-I/opt/homebrew/include"
export CGO_LDFLAGS="-L/opt/homebrew/lib -lcrypto"
```

Then reload your shell:
```bash
source ~/.zshrc  # or ~/.bashrc
```

## Running Tests

```bash
make test
```

## Notes

- **SEV-SNP Support**: The real SEV-SNP attestation requires running on an AMD EPYC processor with SEV-SNP enabled and access to `/dev/sev-guest`. For development/testing on non-SEV hardware, use `attestation.provider = "simulated"` in the config.

- **OpenSSL Version**: This project requires OpenSSL 1.1.1 or later (OpenSSL 3.x recommended). Check your version:
  ```bash
  openssl version
  ```

- **CGo Required**: This project uses CGo to interface with the SEV-SNP kernel driver, so `CGO_ENABLED=1` is required (it's the default).
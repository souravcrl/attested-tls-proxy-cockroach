package attestation

/*
#cgo LDFLAGS: -lcrypto
#include <stdint.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>

// SEV-SNP ioctl commands
// Reference: linux/include/uapi/linux/sev-guest.h
#define SNP_GET_REPORT _IOWR('S', 0x01, struct snp_guest_request_ioctl)
#define SNP_GET_DERIVED_KEY _IOWR('S', 0x02, struct snp_guest_request_ioctl)
#define SNP_GET_EXT_REPORT _IOWR('S', 0x03, struct snp_guest_request_ioctl)

// ioctl request structure
struct snp_guest_request_ioctl {
    uint64_t req_data;
    uint64_t resp_data;
    uint64_t exit_info2;
};

// Request structure for SNP_GET_REPORT
struct snp_report_req {
    uint8_t report_data[64];  // User-provided nonce
    uint32_t vmpl;            // VM Permission Level
    uint8_t rsvd[28];         // Reserved
};

// Response structure for SNP_GET_REPORT
struct snp_report_resp {
    uint32_t status;          // Status code
    uint32_t report_size;     // Size of report
    uint8_t rsvd[24];         // Reserved
    uint8_t report[1184];     // The actual attestation report
};

// Wrapper function to call ioctl safely
static int get_attestation_report(int fd, uint8_t *nonce, size_t nonce_len, uint8_t *report_out, uint64_t *exit_info2) {
    struct snp_report_req req;
    struct snp_report_resp resp;
    struct snp_guest_request_ioctl ioctl_req;

    // Zero out structures
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    memset(&ioctl_req, 0, sizeof(ioctl_req));

    // Copy nonce to request (max 64 bytes)
    if (nonce_len > 64) {
        nonce_len = 64;
    }
    memcpy(req.report_data, nonce, nonce_len);
    req.vmpl = 0;  // VM Permission Level 0 (most privileged)

    // Setup ioctl request
    ioctl_req.req_data = (uint64_t)&req;
    ioctl_req.resp_data = (uint64_t)&resp;
    ioctl_req.exit_info2 = 0;

    // Call ioctl
    int ret = ioctl(fd, SNP_GET_REPORT, &ioctl_req);
    if (ret != 0) {
        *exit_info2 = ioctl_req.exit_info2;
        return ret;
    }

    // Check response status
    if (resp.status != 0) {
        return -1;
    }

    // Copy report to output
    memcpy(report_out, resp.report, 1184);
    *exit_info2 = ioctl_req.exit_info2;

    return 0;
}
*/
import "C"

import (
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"os"
	"syscall"
	"time"
	"unsafe"

	"github.com/souravcrl/attested-tls-proxy-cockroach/internal/logger"
)

// SEVSNPAttester implements the Attester interface using real SEV-SNP hardware
type SEVSNPAttester struct {
	deviceFd int
}

// NewSEVSNPAttester creates a new SEV-SNP attester
func NewSEVSNPAttester() (*SEVSNPAttester, error) {
	// Try to open the SEV guest device
	fd, err := syscall.Open(SEVGuestDevice, syscall.O_RDWR, 0)
	if err != nil {
		// If device doesn't exist, this is not a SEV-SNP VM
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("SEV-SNP device %s not found - not running in SEV-SNP VM", SEVGuestDevice)
		}
		return nil, fmt.Errorf("failed to open %s: %w", SEVGuestDevice, err)
	}

	logger.Log.Info().
		Str("device", SEVGuestDevice).
		Msg("SEV-SNP attester initialized")

	return &SEVSNPAttester{
		deviceFd: fd,
	}, nil
}

// GetReport fetches an attestation report with the given nonce
func (a *SEVSNPAttester) GetReport(nonce []byte) (*AttestationEvidence, error) {
	if len(nonce) > MaxNonceSize {
		return nil, fmt.Errorf("nonce too large (max %d bytes): got %d", MaxNonceSize, len(nonce))
	}

	logger.Log.Debug().
		Int("nonce_len", len(nonce)).
		Msg("Requesting SEV-SNP attestation report")

	// Prepare buffer for report
	reportBuf := make([]byte, ReportSize)
	var exitInfo2 C.uint64_t

	// Call ioctl via CGo
	nonceBuf := make([]byte, MaxNonceSize)
	copy(nonceBuf, nonce)

	ret := C.get_attestation_report(
		C.int(a.deviceFd),
		(*C.uint8_t)(unsafe.Pointer(&nonceBuf[0])),
		C.size_t(len(nonce)),
		(*C.uint8_t)(unsafe.Pointer(&reportBuf[0])),
		&exitInfo2,
	)

	if ret != 0 {
		return nil, fmt.Errorf("ioctl SNP_GET_REPORT failed: ret=%d, exit_info2=0x%x, errno=%d",
			ret, exitInfo2, syscall.Errno(ret))
	}

	// Parse the report
	report, err := ParseReport(reportBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to parse attestation report: %w", err)
	}

	logger.Log.Info().
		Str("tcb_version", report.GetTCBVersion()).
		Bool("debug_enabled", report.IsDebugEnabled()).
		Bool("smt_enabled", report.IsSMTEnabled()).
		Msg("SEV-SNP attestation report retrieved")

	return &AttestationEvidence{
		Report:       report,
		Certificates: nil, // Will be fetched by GetExtendedReport
		Nonce:        nonce,
		Timestamp:    getCurrentTimestamp(),
	}, nil
}

// GetExtendedReport fetches a report with the AMD certificate chain
func (a *SEVSNPAttester) GetExtendedReport(nonce []byte) (*AttestationEvidence, error) {
	// First get the basic report
	evidence, err := a.GetReport(nonce)
	if err != nil {
		return nil, err
	}

	// Fetch certificates from AMD KDS
	logger.Log.Info().Msg("Fetching AMD certificate chain from KDS")

	certs, err := a.fetchCertificateChain(evidence.Report.ChipID)
	if err != nil {
		logger.Log.Warn().
			Err(err).
			Msg("Failed to fetch AMD certificates - proceeding without chain")
		// Don't fail completely - some verifiers may accept reports without certs
		certs = [][]byte{}
	}

	evidence.Certificates = certs
	return evidence, nil
}

// Close closes the SEV-SNP device
func (a *SEVSNPAttester) Close() error {
	if a.deviceFd > 0 {
		err := syscall.Close(a.deviceFd)
		if err != nil {
			return fmt.Errorf("failed to close SEV device: %w", err)
		}
		logger.Log.Info().Msg("SEV-SNP attester closed")
	}
	return nil
}

// fetchCertificateChain fetches the VCEK, ASK, and ARK certificates from AMD KDS
func (a *SEVSNPAttester) fetchCertificateChain(chipID [64]byte) ([][]byte, error) {
	// AMD Key Distribution Service (KDS) base URL
	const kdsBaseURL = "https://kdsintf.amd.com/vcek/v1"

	// Product name for Milan (SEV-SNP)
	const productName = "Milan"

	// Convert chip ID to hex string
	chipIDHex := fmt.Sprintf("%x", chipID)

	// Construct VCEK URL
	// Format: https://kdsintf.amd.com/vcek/v1/{product}/{hwid}
	vcekURL := fmt.Sprintf("%s/%s/%s", kdsBaseURL, productName, chipIDHex)

	logger.Log.Debug().
		Str("url", vcekURL).
		Msg("Fetching VCEK certificate")

	// Fetch VCEK
	vcek, err := fetchCertificate(vcekURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch VCEK: %w", err)
	}

	// Fetch ASK (AMD SEV Signing Key)
	askURL := fmt.Sprintf("%s/%s/cert_chain", kdsBaseURL, productName)
	logger.Log.Debug().
		Str("url", askURL).
		Msg("Fetching ASK certificate chain")

	certChain, err := fetchCertificate(askURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch ASK/ARK chain: %w", err)
	}

	// The cert_chain endpoint returns ASK + ARK in PEM format
	// For now, return as single blob - will parse in verification
	return [][]byte{vcek, certChain}, nil
}

// fetchCertificate fetches a certificate from a URL
func fetchCertificate(url string) ([]byte, error) {
	client := &http.Client{
		Timeout: 30 * getCurrentDuration(),
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %d %s", resp.StatusCode, resp.Status)
	}

	cert, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return cert, nil
}

// GenerateNonce generates a cryptographically secure random nonce
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, 32) // 32 bytes = 256 bits
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return nonce, nil
}

// Helper functions
func getCurrentTimestamp() int64 {
	return time.Now().Unix()
}

func getCurrentDuration() time.Duration {
	return time.Second
}

// NewAttester creates an appropriate attester based on configuration
func NewAttester(provider string) (Attester, error) {
	switch provider {
	case "sev-snp":
		return NewSEVSNPAttester()
	case "simulated", "mock":
		logger.Log.Warn().Msg("Using SIMULATED attestation - DO NOT USE IN PRODUCTION")
		return NewMockAttester(), nil
	default:
		return nil, fmt.Errorf("unknown attestation provider: %s", provider)
	}
}
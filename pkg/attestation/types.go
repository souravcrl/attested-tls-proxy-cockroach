package attestation

import (
	"encoding/binary"
	"fmt"
	"time"
)

// AMD SEV-SNP Attestation Report Structure
// Reference: AMD SEV-SNP ABI Specification, Section 7.3

const (
	// SEV-SNP device path
	SEVGuestDevice = "/dev/sev-guest"

	// Report size is fixed at 1184 bytes
	ReportSize = 1184

	// Maximum nonce size (REPORT_DATA field)
	MaxNonceSize = 64
)

// AttestationReport represents an AMD SEV-SNP attestation report (1184 bytes)
type AttestationReport struct {
	// Version of the attestation report (offset 0x000, 4 bytes)
	Version uint32

	// Guest SVN (Security Version Number) (offset 0x004, 4 bytes)
	GuestSVN uint32

	// Guest policy (offset 0x008, 8 bytes)
	// Bit 0: Debugging allowed
	// Bit 1-15: ABI minor version
	// Bit 16-31: ABI major version
	// Bit 32-47: SMT allowed
	Policy uint64

	// Family ID (offset 0x010, 16 bytes)
	FamilyID [16]byte

	// Image ID (offset 0x020, 16 bytes)
	ImageID [16]byte

	// VMPL (VM Permission Level) (offset 0x030, 4 bytes)
	VMPL uint32

	// Signature algorithm (offset 0x034, 4 bytes)
	// 1 = ECDSA P-384 with SHA-384
	SignatureAlgo uint32

	// Current TCB version (offset 0x038, 8 bytes)
	PlatformVersion uint64

	// Platform info flags (offset 0x040, 8 bytes)
	PlatformInfo uint64

	// Author key flags (offset 0x048, 4 bytes)
	AuthorKeyEn uint32

	// Reserved (offset 0x04C, 4 bytes)
	Reserved1 uint32

	// Report data (user-provided nonce) (offset 0x050, 64 bytes)
	ReportData [64]byte

	// Measurement (SHA-384 of VM firmware/kernel/app) (offset 0x090, 48 bytes)
	// This is the key field for attestation!
	Measurement [48]byte

	// Host-provided data (offset 0x0C0, 32 bytes)
	HostData [32]byte

	// ID key digest (offset 0x0E0, 48 bytes)
	IDKeyDigest [48]byte

	// Author key digest (offset 0x110, 48 bytes)
	AuthorKeyDigest [48]byte

	// Report ID (offset 0x140, 32 bytes)
	ReportID [32]byte

	// Report ID MA (Migration Agent) (offset 0x160, 32 bytes)
	ReportIDMA [32]byte

	// Reported TCB version (offset 0x180, 8 bytes)
	ReportedTCB uint64

	// Reserved (offset 0x188, 24 bytes)
	Reserved2 [24]byte

	// Chip ID (offset 0x1A0, 64 bytes)
	ChipID [64]byte

	// Committed TCB version (offset 0x1E0, 8 bytes)
	CommittedTCB uint64

	// Current build number (offset 0x1E8, 1 byte)
	CurrentBuild uint8

	// Current minor version (offset 0x1E9, 1 byte)
	CurrentMinor uint8

	// Current major version (offset 0x1EA, 1 byte)
	CurrentMajor uint8

	// Reserved (offset 0x1EB, 1 byte)
	Reserved3 uint8

	// Committed build number (offset 0x1EC, 1 byte)
	CommittedBuild uint8

	// Committed minor version (offset 0x1ED, 1 byte)
	CommittedMinor uint8

	// Committed major version (offset 0x1EE, 1 byte)
	CommittedMajor uint8

	// Reserved (offset 0x1EF, 1 byte)
	Reserved4 uint8

	// Launch TCB (offset 0x1F0, 8 bytes)
	LaunchTCB uint64

	// Reserved (offset 0x1F8, 168 bytes)
	Reserved5 [168]byte

	// Signature (ECDSA P-384) (offset 0x2A0, 512 bytes)
	// R component (48 bytes) + S component (48 bytes) + padding
	Signature [512]byte
}

// AttestationEvidence contains the complete attestation evidence
type AttestationEvidence struct {
	// The attestation report from SEV-SNP
	Report *AttestationReport

	// Certificate chain: VCEK, ASK, ARK
	Certificates [][]byte

	// Nonce used in the report
	Nonce []byte

	// Timestamp when evidence was generated
	Timestamp int64
}

// ParseReport parses a raw attestation report from bytes
func ParseReport(data []byte) (*AttestationReport, error) {
	if len(data) < ReportSize {
		return nil, fmt.Errorf("invalid report size: got %d, expected %d", len(data), ReportSize)
	}

	report := &AttestationReport{}

	// Parse fields using binary encoding (little-endian)
	offset := 0

	report.Version = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	report.GuestSVN = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	report.Policy = binary.LittleEndian.Uint64(data[offset : offset+8])
	offset += 8

	copy(report.FamilyID[:], data[offset:offset+16])
	offset += 16

	copy(report.ImageID[:], data[offset:offset+16])
	offset += 16

	report.VMPL = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	report.SignatureAlgo = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	report.PlatformVersion = binary.LittleEndian.Uint64(data[offset : offset+8])
	offset += 8

	report.PlatformInfo = binary.LittleEndian.Uint64(data[offset : offset+8])
	offset += 8

	report.AuthorKeyEn = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	report.Reserved1 = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	copy(report.ReportData[:], data[offset:offset+64])
	offset += 64

	copy(report.Measurement[:], data[offset:offset+48])
	offset += 48

	copy(report.HostData[:], data[offset:offset+32])
	offset += 32

	copy(report.IDKeyDigest[:], data[offset:offset+48])
	offset += 48

	copy(report.AuthorKeyDigest[:], data[offset:offset+48])
	offset += 48

	copy(report.ReportID[:], data[offset:offset+32])
	offset += 32

	copy(report.ReportIDMA[:], data[offset:offset+32])
	offset += 32

	report.ReportedTCB = binary.LittleEndian.Uint64(data[offset : offset+8])
	offset += 8

	copy(report.Reserved2[:], data[offset:offset+24])
	offset += 24

	copy(report.ChipID[:], data[offset:offset+64])
	offset += 64

	report.CommittedTCB = binary.LittleEndian.Uint64(data[offset : offset+8])
	offset += 8

	report.CurrentBuild = data[offset]
	offset++
	report.CurrentMinor = data[offset]
	offset++
	report.CurrentMajor = data[offset]
	offset++
	report.Reserved3 = data[offset]
	offset++

	report.CommittedBuild = data[offset]
	offset++
	report.CommittedMinor = data[offset]
	offset++
	report.CommittedMajor = data[offset]
	offset++
	report.Reserved4 = data[offset]
	offset++

	report.LaunchTCB = binary.LittleEndian.Uint64(data[offset : offset+8])
	offset += 8

	copy(report.Reserved5[:], data[offset:offset+168])
	offset += 168

	copy(report.Signature[:], data[offset:offset+512])

	return report, nil
}

// Marshal converts the report back to bytes
func (r *AttestationReport) Marshal() []byte {
	data := make([]byte, ReportSize)
	offset := 0

	binary.LittleEndian.PutUint32(data[offset:], r.Version)
	offset += 4

	binary.LittleEndian.PutUint32(data[offset:], r.GuestSVN)
	offset += 4

	binary.LittleEndian.PutUint64(data[offset:], r.Policy)
	offset += 8

	copy(data[offset:], r.FamilyID[:])
	offset += 16

	copy(data[offset:], r.ImageID[:])
	offset += 16

	binary.LittleEndian.PutUint32(data[offset:], r.VMPL)
	offset += 4

	binary.LittleEndian.PutUint32(data[offset:], r.SignatureAlgo)
	offset += 4

	binary.LittleEndian.PutUint64(data[offset:], r.PlatformVersion)
	offset += 8

	binary.LittleEndian.PutUint64(data[offset:], r.PlatformInfo)
	offset += 8

	binary.LittleEndian.PutUint32(data[offset:], r.AuthorKeyEn)
	offset += 4

	binary.LittleEndian.PutUint32(data[offset:], r.Reserved1)
	offset += 4

	copy(data[offset:], r.ReportData[:])
	offset += 64

	copy(data[offset:], r.Measurement[:])
	offset += 48

	copy(data[offset:], r.HostData[:])
	offset += 32

	copy(data[offset:], r.IDKeyDigest[:])
	offset += 48

	copy(data[offset:], r.AuthorKeyDigest[:])
	offset += 48

	copy(data[offset:], r.ReportID[:])
	offset += 32

	copy(data[offset:], r.ReportIDMA[:])
	offset += 32

	binary.LittleEndian.PutUint64(data[offset:], r.ReportedTCB)
	offset += 8

	copy(data[offset:], r.Reserved2[:])
	offset += 24

	copy(data[offset:], r.ChipID[:])
	offset += 64

	binary.LittleEndian.PutUint64(data[offset:], r.CommittedTCB)
	offset += 8

	data[offset] = r.CurrentBuild
	offset++
	data[offset] = r.CurrentMinor
	offset++
	data[offset] = r.CurrentMajor
	offset++
	data[offset] = r.Reserved3
	offset++

	data[offset] = r.CommittedBuild
	offset++
	data[offset] = r.CommittedMinor
	offset++
	data[offset] = r.CommittedMajor
	offset++
	data[offset] = r.Reserved4
	offset++

	binary.LittleEndian.PutUint64(data[offset:], r.LaunchTCB)
	offset += 8

	copy(data[offset:], r.Reserved5[:])
	offset += 168

	copy(data[offset:], r.Signature[:])

	return data
}

// GetTCBVersion returns a formatted TCB version string
func (r *AttestationReport) GetTCBVersion() string {
	return fmt.Sprintf("%d.%d.%d",
		r.CurrentMajor,
		r.CurrentMinor,
		r.CurrentBuild)
}

// IsDebugEnabled checks if debugging is enabled (Policy bit 0)
func (r *AttestationReport) IsDebugEnabled() bool {
	return (r.Policy & 0x01) != 0
}

// IsSMTEnabled checks if SMT is enabled (Policy bits 32-47)
func (r *AttestationReport) IsSMTEnabled() bool {
	return ((r.Policy >> 32) & 0xFFFF) != 0
}

// GetNonce extracts the nonce from ReportData
func (r *AttestationReport) GetNonce() []byte {
	// Find the actual length (trim trailing zeros)
	for i := len(r.ReportData) - 1; i >= 0; i-- {
		if r.ReportData[i] != 0 {
			return r.ReportData[:i+1]
		}
	}
	return []byte{}
}

// Attester provides methods to request attestation reports
type Attester interface {
	// GetReport fetches an attestation report with the given nonce
	GetReport(nonce []byte) (*AttestationEvidence, error)

	// GetExtendedReport fetches a report with certificate chain
	GetExtendedReport(nonce []byte) (*AttestationEvidence, error)

	// Close closes the attester
	Close() error
}

// Mock attester for development/testing
type MockAttester struct {
	reports map[string]*AttestationEvidence
}

// NewMockAttester creates a mock attester for testing
func NewMockAttester() *MockAttester {
	return &MockAttester{
		reports: make(map[string]*AttestationEvidence),
	}
}

// GetReport returns a mock attestation report
func (m *MockAttester) GetReport(nonce []byte) (*AttestationEvidence, error) {
	// Create a fake report for testing
	report := &AttestationReport{
		Version:      1,
		GuestSVN:     1,
		Policy:       0x30000, // No debug, no SMT
		SignatureAlgo: 1,      // ECDSA P-384
		CurrentMajor: 1,
		CurrentMinor: 51,
		CurrentBuild: 0,
	}

	// Copy nonce to report data
	copy(report.ReportData[:], nonce)

	// Fake measurement (for testing)
	copy(report.Measurement[:], []byte("MOCK_MEASUREMENT_FOR_TESTING_ONLY_____"))

	return &AttestationEvidence{
		Report:       report,
		Certificates: [][]byte{}, // No certs for mock
		Nonce:        nonce,
		Timestamp:    time.Now().Unix(),
	}, nil
}

// GetExtendedReport returns a mock report with fake certificates
func (m *MockAttester) GetExtendedReport(nonce []byte) (*AttestationEvidence, error) {
	evidence, err := m.GetReport(nonce)
	if err != nil {
		return nil, err
	}

	// Add fake certificate chain
	evidence.Certificates = [][]byte{
		[]byte("MOCK_VCEK_CERTIFICATE"),
		[]byte("MOCK_ASK_CERTIFICATE"),
		[]byte("MOCK_ARK_CERTIFICATE"),
	}

	return evidence, nil
}

// Close closes the mock attester
func (m *MockAttester) Close() error {
	return nil
}
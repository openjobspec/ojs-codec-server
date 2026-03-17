// tee.go — M1/P2 sliver: structural validation of TEE quote/report
// headers attached to ext_attest evidence. We do NOT (yet) verify the
// quote signature against an Intel/AMD root of trust — that requires the
// full Intel SGX QvL / AMD SNP cert-chain plumbing tracked in M1/P3.
// What this DOES do is reject documents that obviously aren't a TDX
// quote or SEV-SNP report (truncated, wrong version, wrong TEE-type),
// which today the verifier accepts as long as the ed25519 signature is
// valid. That gap is exploitable: a signer with a valid key can attach
// arbitrary bytes as "intel-tdx" evidence and downstream auditors have
// no way to tell.
//
// References (read 2026-04-17):
//   - Intel TDX Quoting Library Reference, v1.0,
//     https://www.intel.com/content/dam/develop/external/us/en/documents/intel-tdx-dcap-quoting-library-api.pdf
//   - AMD SEV-SNP Firmware ABI Specification, rev 1.55,
//     https://www.amd.com/system/files/TechDocs/56860.pdf §7.1 ATTESTATION_REPORT
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// tdxQuoteMinSize is the smallest structurally-valid TDX quote: header
// (48 bytes) + report body (584 bytes) + signature data length prefix
// (4 bytes). Any shorter is truncated.
const tdxQuoteMinSize = 48 + 584 + 4

// snpReportMinSize is the SNP attestation report fixed-layout size per
// §7.3 of the firmware ABI spec.
const snpReportMinSize = 0x4A0

// teeQuoteInfo summarises what we recovered from the document header.
// Returned for logging by verify so operators can sanity-check
// expectations without enabling debug output.
type teeQuoteInfo struct {
	Type           string // "intel-tdx" or "amd-sev-snp"
	Version        uint32
	TEEType        uint32 // TDX-specific (0x00000081 = TDX, 0 = SGX)
	AKType         uint16 // attestation key type (TDX only)
	ReportDataHash []byte // first 32 bytes of report-data field, for cross-check
}

// validateTEEDocument decodes the header of a quote/report blob and
// asserts it matches the declared evidence type. Returns a teeQuoteInfo
// summary on success; an error otherwise. The returned info is suitable
// for inclusion in human-readable verifier output.
func validateTEEDocument(declaredType string, doc []byte) (teeQuoteInfo, error) {
	switch declaredType {
	case "intel-tdx":
		return validateTDXQuote(doc)
	case "amd-sev-snp":
		return validateSNPReport(doc)
	case "aws-nitro":
		return validateNitroAttestation(doc)
	default:
		return teeQuoteInfo{}, fmt.Errorf("validateTEEDocument: declared type %q is not a TEE", declaredType)
	}
}

// validateTDXQuote inspects the first 48 bytes of an Intel TDX quote.
// Layout (all little-endian):
//
//	offset  size  field
//	------  ----  ----------------------------------
//	0       2     Version (must be 4 for TDX 1.0; 5 for 1.5)
//	2       2     AttestationKeyType (2=ECDSA-P256, 3=ECDSA-P384)
//	4       4     TEEType (0x00000081 = TDX, 0 = SGX)
//	8       4     Reserved (must be zero)
//	12      16    VendorID (should be "Intel SGX QE")
//	28      20    UserData (free-form)
func validateTDXQuote(doc []byte) (teeQuoteInfo, error) {
	if len(doc) < tdxQuoteMinSize {
		return teeQuoteInfo{}, fmt.Errorf("tdx quote: %d bytes is below minimum %d", len(doc), tdxQuoteMinSize)
	}
	version := binary.LittleEndian.Uint16(doc[0:2])
	if version != 4 && version != 5 {
		return teeQuoteInfo{}, fmt.Errorf("tdx quote: version %d not supported (want 4 or 5)", version)
	}
	akType := binary.LittleEndian.Uint16(doc[2:4])
	if akType != 2 && akType != 3 {
		return teeQuoteInfo{}, fmt.Errorf("tdx quote: AKType %d not in {2,3}", akType)
	}
	teeType := binary.LittleEndian.Uint32(doc[4:8])
	if teeType != 0x00000081 {
		return teeQuoteInfo{}, fmt.Errorf("tdx quote: TEEType 0x%x is not TDX (want 0x81)", teeType)
	}
	reserved := binary.LittleEndian.Uint32(doc[8:12])
	if reserved != 0 {
		return teeQuoteInfo{}, fmt.Errorf("tdx quote: reserved bytes nonzero (0x%x)", reserved)
	}
	// Vendor ID is informational; we record it but don't require an
	// exact match because Intel has shipped variations across QvL
	// versions.
	// report_data is the first 32 bytes of the TD_REPORT body, which
	// starts at offset 48.
	reportData := append([]byte(nil), doc[48:48+32]...)
	return teeQuoteInfo{
		Type:           "intel-tdx",
		Version:        uint32(version),
		TEEType:        teeType,
		AKType:         akType,
		ReportDataHash: reportData,
	}, nil
}

// validateSNPReport inspects an AMD SEV-SNP ATTESTATION_REPORT structure.
// Layout (relevant fields only, little-endian):
//
//	offset  size  field
//	------  ----  ----------------------------------
//	0       4     Version (2 or 3)
//	4       4     GuestSVN
//	8       8     Policy
//	16      16    FamilyID
//	32      16    ImageID
//	48      4     VMPL (must be 0..3)
//	52      4     SignatureAlgo (1=ECDSA-P384-SHA384)
//	...
//	0x50    64    REPORT_DATA (user-supplied nonce)
func validateSNPReport(doc []byte) (teeQuoteInfo, error) {
	if len(doc) < snpReportMinSize {
		return teeQuoteInfo{}, fmt.Errorf("snp report: %d bytes below minimum %d", len(doc), snpReportMinSize)
	}
	version := binary.LittleEndian.Uint32(doc[0:4])
	if version != 2 && version != 3 {
		return teeQuoteInfo{}, fmt.Errorf("snp report: version %d not supported (want 2 or 3)", version)
	}
	vmpl := binary.LittleEndian.Uint32(doc[48:52])
	if vmpl > 3 {
		return teeQuoteInfo{}, fmt.Errorf("snp report: VMPL %d > 3", vmpl)
	}
	sigAlgo := binary.LittleEndian.Uint32(doc[52:56])
	if sigAlgo != 1 {
		return teeQuoteInfo{}, fmt.Errorf("snp report: SignatureAlgo %d not ECDSA-P384-SHA384(1)", sigAlgo)
	}
	// REPORT_DATA is at offset 0x50 (80) in v2 layout. We snapshot
	// the first 32 bytes for cross-check with InputDigest.
	if len(doc) < 0x50+32 {
		return teeQuoteInfo{}, errors.New("snp report: truncated before REPORT_DATA")
	}
	reportData := append([]byte(nil), doc[0x50:0x50+32]...)
	return teeQuoteInfo{
		Type:           "amd-sev-snp",
		Version:        version,
		ReportDataHash: reportData,
	}, nil
}

// validateNitroAttestation does a minimal smoke check on AWS Nitro
// Enclaves attestation documents. The full spec uses COSE_Sign1 with
// CBOR; verifying the cert chain is a separate quarter (M1/P3). For now
// we just assert the document starts with the COSE tag (0xD2) per
// RFC 9052, and is at least header-sized.
func validateNitroAttestation(doc []byte) (teeQuoteInfo, error) {
	const minSize = 256 // empirical lower bound for a real attestation
	if len(doc) < minSize {
		return teeQuoteInfo{}, fmt.Errorf("nitro: doc %d bytes below smoke minimum %d", len(doc), minSize)
	}
	// CBOR tag 18 (COSE_Sign1) major type 6 = 0xC0|0x12 = 0xD2.
	if doc[0] != 0xD2 {
		return teeQuoteInfo{}, fmt.Errorf("nitro: first byte 0x%02x is not COSE_Sign1 tag (0xD2)", doc[0])
	}
	return teeQuoteInfo{Type: "aws-nitro"}, nil
}

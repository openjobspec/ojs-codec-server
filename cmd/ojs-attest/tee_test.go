package main

import (
	"encoding/binary"
	"strings"
	"testing"
)

// helper: pad a buffer up to n bytes.
func pad(buf []byte, n int) []byte {
	if len(buf) >= n {
		return buf
	}
	return append(buf, make([]byte, n-len(buf))...)
}

func TestValidateTDXQuoteHappy(t *testing.T) {
	doc := make([]byte, 48)
	binary.LittleEndian.PutUint16(doc[0:2], 4)            // version 4
	binary.LittleEndian.PutUint16(doc[2:4], 2)            // ECDSA-P256
	binary.LittleEndian.PutUint32(doc[4:8], 0x00000081)   // TDX
	doc = pad(doc, tdxQuoteMinSize)

	info, err := validateTEEDocument("intel-tdx", doc)
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != 4 || info.TEEType != 0x81 || info.AKType != 2 {
		t.Errorf("info = %+v", info)
	}
	if len(info.ReportDataHash) != 32 {
		t.Errorf("report data hash len %d, want 32", len(info.ReportDataHash))
	}
}

func TestValidateTDXTooShort(t *testing.T) {
	if _, err := validateTEEDocument("intel-tdx", make([]byte, 10)); err == nil {
		t.Error("expected error on truncated TDX quote")
	}
}

func TestValidateTDXWrongVersion(t *testing.T) {
	doc := make([]byte, tdxQuoteMinSize)
	binary.LittleEndian.PutUint16(doc[0:2], 7) // not 4 or 5
	binary.LittleEndian.PutUint16(doc[2:4], 2)
	binary.LittleEndian.PutUint32(doc[4:8], 0x81)
	if _, err := validateTEEDocument("intel-tdx", doc); err == nil || !strings.Contains(err.Error(), "version 7") {
		t.Errorf("expected version-7 rejection, got %v", err)
	}
}

func TestValidateTDXWrongTEEType(t *testing.T) {
	doc := make([]byte, tdxQuoteMinSize)
	binary.LittleEndian.PutUint16(doc[0:2], 4)
	binary.LittleEndian.PutUint16(doc[2:4], 2)
	binary.LittleEndian.PutUint32(doc[4:8], 0) // SGX, not TDX
	if _, err := validateTEEDocument("intel-tdx", doc); err == nil || !strings.Contains(err.Error(), "TEEType") {
		t.Errorf("expected TEEType rejection, got %v", err)
	}
}

func TestValidateTDXReservedNonzero(t *testing.T) {
	doc := make([]byte, tdxQuoteMinSize)
	binary.LittleEndian.PutUint16(doc[0:2], 4)
	binary.LittleEndian.PutUint16(doc[2:4], 2)
	binary.LittleEndian.PutUint32(doc[4:8], 0x81)
	binary.LittleEndian.PutUint32(doc[8:12], 0xDEADBEEF)
	if _, err := validateTEEDocument("intel-tdx", doc); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Errorf("expected reserved-bytes rejection, got %v", err)
	}
}

func TestValidateSNPHappy(t *testing.T) {
	doc := make([]byte, snpReportMinSize)
	binary.LittleEndian.PutUint32(doc[0:4], 2)   // version 2
	binary.LittleEndian.PutUint32(doc[48:52], 0) // VMPL 0
	binary.LittleEndian.PutUint32(doc[52:56], 1) // ECDSA-P384
	info, err := validateTEEDocument("amd-sev-snp", doc)
	if err != nil {
		t.Fatal(err)
	}
	if info.Type != "amd-sev-snp" || info.Version != 2 {
		t.Errorf("info = %+v", info)
	}
}

func TestValidateSNPRejectsBadAlgo(t *testing.T) {
	doc := make([]byte, snpReportMinSize)
	binary.LittleEndian.PutUint32(doc[0:4], 2)
	binary.LittleEndian.PutUint32(doc[52:56], 999) // not 1
	if _, err := validateTEEDocument("amd-sev-snp", doc); err == nil {
		t.Error("expected SignatureAlgo rejection")
	}
}

func TestValidateSNPVMPLBounds(t *testing.T) {
	doc := make([]byte, snpReportMinSize)
	binary.LittleEndian.PutUint32(doc[0:4], 2)
	binary.LittleEndian.PutUint32(doc[48:52], 99) // > 3
	binary.LittleEndian.PutUint32(doc[52:56], 1)
	if _, err := validateTEEDocument("amd-sev-snp", doc); err == nil {
		t.Error("expected VMPL out-of-range rejection")
	}
}

func TestValidateNitroHappy(t *testing.T) {
	doc := make([]byte, 256)
	doc[0] = 0xD2 // COSE_Sign1 tag
	if _, err := validateTEEDocument("aws-nitro", doc); err != nil {
		t.Fatal(err)
	}
}

func TestValidateNitroBadTag(t *testing.T) {
	doc := make([]byte, 256)
	doc[0] = 0xAA
	if _, err := validateTEEDocument("aws-nitro", doc); err == nil {
		t.Error("expected COSE tag rejection")
	}
}

func TestValidateUnknownType(t *testing.T) {
	if _, err := validateTEEDocument("signature-only", []byte{}); err == nil {
		t.Error("expected error: signature-only is not a TEE")
	}
}

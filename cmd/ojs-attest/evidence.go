package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// AttestationEvidence is duplicated from ojs-conformance/lib/attestation.go
// on purpose: each module in this multi-repo org is independently
// versioned, so cross-module dependencies are deliberately avoided in
// CLIs. The validator and verifier MUST stay byte-compatible with
// ojs-conformance/lib; that's enforced by RFC-0010 + golden tests in
// each module.
type AttestationEvidence struct {
	Version      int    `json:"v"`
	Algorithm    string `json:"alg"`
	Type         string `json:"type"`
	KeyID        string `json:"key_id"`
	InputDigest  string `json:"input_digest"`
	OutputDigest string `json:"output_digest,omitempty"`
	Document     string `json:"document,omitempty"`
	Signature    string `json:"signature"`
	SignedAt     string `json:"signed_at"`
}

var knownTypes = map[string]struct{}{
	"signature-only": {},
	"aws-nitro":      {},
	"intel-tdx":      {},
	"amd-sev-snp":    {},
}

type attestationEvidenceSigner struct {
	privateKey ed25519.PrivateKey
	keyID      string
	attestType string
}

func (s attestationEvidenceSigner) Sign(inputDigest, outputDigest string, document []byte) AttestationEvidence {
	signature := ed25519.Sign(s.privateKey, signingPayload(inputDigest, outputDigest, document))
	evidence := AttestationEvidence{
		Version:      1,
		Algorithm:    "ed25519",
		Type:         s.attestType,
		KeyID:        s.keyID,
		InputDigest:  inputDigest,
		OutputDigest: outputDigest,
		Document:     base64.StdEncoding.EncodeToString(document),
		Signature:    base64.StdEncoding.EncodeToString(signature),
		SignedAt:     time.Now().UTC().Format(time.RFC3339),
	}
	if document == nil {
		evidence.Document = ""
	}
	return evidence
}

type attestationEvidenceVerifier struct {
	publicKey ed25519.PublicKey
	freshness time.Duration
}

type evidenceVerification struct {
	tee *teeQuoteInfo
}

func (v attestationEvidenceVerifier) Verify(evidence AttestationEvidence) (evidenceVerification, error) {
	if err := evidence.validate(); err != nil {
		return evidenceVerification{}, err
	}
	if evidence.Algorithm != "ed25519" {
		return evidenceVerification{}, fmt.Errorf("verify: algorithm %q not supported by P1 verifier", evidence.Algorithm)
	}
	if evidence.Type != "signature-only" && evidence.Document == "" {
		return evidenceVerification{}, fmt.Errorf("verify: type %q requires non-empty document", evidence.Type)
	}
	signedAt, _ := time.Parse(time.RFC3339, evidence.SignedAt)
	if v.freshness > 0 && time.Since(signedAt) > v.freshness {
		return evidenceVerification{}, fmt.Errorf("verify: signed_at %s exceeds freshness window %s", evidence.SignedAt, v.freshness)
	}
	signature, _ := base64.StdEncoding.DecodeString(evidence.Signature)
	document, _ := base64.StdEncoding.DecodeString(evidence.Document)
	if !ed25519.Verify(v.publicKey, signingPayload(evidence.InputDigest, evidence.OutputDigest, document), signature) {
		return evidenceVerification{}, errors.New("verify: signature invalid")
	}

	// TEE evidence receives structural header validation here; certificate
	// chain and quote-signature verification remain outside the P1 verifier.
	if evidence.Type == "intel-tdx" || evidence.Type == "amd-sev-snp" || evidence.Type == "aws-nitro" {
		info, err := validateTEEDocument(evidence.Type, document)
		if err != nil {
			return evidenceVerification{}, fmt.Errorf("verify: tee document: %w", err)
		}
		return evidenceVerification{tee: &info}, nil
	}
	return evidenceVerification{}, nil
}

func (e *AttestationEvidence) validate() error {
	if e.Version != 1 {
		return fmt.Errorf("validate: unsupported version %d", e.Version)
	}
	if _, ok := knownTypes[e.Type]; !ok {
		return fmt.Errorf("validate: unknown type %q", e.Type)
	}
	if e.KeyID == "" {
		return errors.New("validate: missing key_id")
	}
	if !strings.HasPrefix(e.InputDigest, "sha256:") || len(e.InputDigest) != len("sha256:")+64 {
		return fmt.Errorf("validate: malformed input_digest %q", e.InputDigest)
	}
	if e.OutputDigest != "" && (!strings.HasPrefix(e.OutputDigest, "sha256:") || len(e.OutputDigest) != len("sha256:")+64) {
		return fmt.Errorf("validate: malformed output_digest %q", e.OutputDigest)
	}
	if _, err := base64.StdEncoding.DecodeString(e.Signature); err != nil {
		return fmt.Errorf("validate: signature not base64: %w", err)
	}
	if e.Document != "" {
		if _, err := base64.StdEncoding.DecodeString(e.Document); err != nil {
			return fmt.Errorf("validate: document not base64: %w", err)
		}
	}
	if _, err := time.Parse(time.RFC3339, e.SignedAt); err != nil {
		return fmt.Errorf("validate: signed_at not RFC 3339: %w", err)
	}
	return nil
}

func canonicalDigest(raw []byte) (string, error) {
	var probe any
	if err := json.Unmarshal(raw, &probe); err != nil {
		return "", err
	}
	canon, err := json.Marshal(probe)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

// signingPayload mirrors ojs-conformance/lib.SigningPayload exactly.
func signingPayload(input, output string, document []byte) []byte {
	const sep = 0x1F
	out := make([]byte, 0, len(input)+1+len(output)+1+len(document))
	out = append(out, []byte(input)...)
	out = append(out, sep)
	out = append(out, []byte(output)...)
	out = append(out, sep)
	out = append(out, document...)
	return out
}

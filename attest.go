package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"
)

// attestPlugin is a combined signer + attestor capability used internally
// by the attestation pipeline. It is not exported because Signer and Attestor
// both define a Verify method with different signatures.
type attestPlugin struct {
	signer   Signer
	attestor Attestor
}

// AttestPipeline chains: encode → sign → attach quote → attach jurisdiction.
// It is the main entry point for producing a verifiable-compute envelope
// inside the codec server.
type AttestPipeline struct {
	signer   Signer
	attestor Attestor
	rotator  *KeyRotator
}

// NewAttestPipeline creates a pipeline backed by the given signer, attestor,
// and key rotator.
func NewAttestPipeline(signer Signer, attestor Attestor, rotator *KeyRotator) *AttestPipeline {
	return &AttestPipeline{signer: signer, attestor: attestor, rotator: rotator}
}

// AttestEnvelope is the result of a full pipeline run.
type AttestEnvelope struct {
	Payload      []byte `json:"payload"`
	Signature    []byte `json:"signature"`
	KeyID        string `json:"key_id"`
	Quote        []byte `json:"quote"`
	Jurisdiction string `json:"jurisdiction"`
	IssuedAt     string `json:"issued_at"`
}

// Run executes the full attestation pipeline for a payload:
// 1. Hash the payload (SHA-256).
// 2. Sign the hash with the current key.
// 3. Produce a hardware/software attestation quote.
// 4. Attach jurisdiction metadata.
func (p *AttestPipeline) Run(ctx context.Context, payload []byte, jurisdiction string) (*AttestEnvelope, error) {
	digest := sha256.Sum256(payload)
	keyID, _ := p.rotator.Current()

	sig, err := p.signer.Sign(ctx, keyID, digest[:])
	if err != nil {
		return nil, fmt.Errorf("attest pipeline: sign: %w", err)
	}

	quote, err := p.attestor.Attest(ctx, digest[:])
	if err != nil {
		return nil, fmt.Errorf("attest pipeline: attest: %w", err)
	}

	return &AttestEnvelope{
		Payload:      payload,
		Signature:    sig,
		KeyID:        keyID,
		Quote:        quote,
		Jurisdiction: jurisdiction,
		IssuedAt:     time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// Verify checks a previously issued envelope against the pipeline's signer
// and attestor.
func (p *AttestPipeline) Verify(ctx context.Context, env *AttestEnvelope) error {
	digest := sha256.Sum256(env.Payload)

	if err := p.rotator.Verify(env.KeyID, digest[:], env.Signature); err != nil {
		return fmt.Errorf("attest pipeline: verify signature: %w", err)
	}

	if err := p.attestor.Verify(ctx, digest[:], env.Quote); err != nil {
		return fmt.Errorf("attest pipeline: verify quote: %w", err)
	}
	return nil
}

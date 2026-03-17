package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
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

// KeyRotator manages attestation signing keys with rotation support.
// It is safe for concurrent use.
type KeyRotator struct {
	mu      sync.RWMutex
	current string
	keys    map[string]ed25519.PrivateKey
}

// NewKeyRotator returns a rotator with an initial keypair.
func NewKeyRotator(keyID string, priv ed25519.PrivateKey) *KeyRotator {
	return &KeyRotator{
		current: keyID,
		keys:    map[string]ed25519.PrivateKey{keyID: priv},
	}
}

// Current returns the active key ID and private key.
func (kr *KeyRotator) Current() (keyID string, privateKey any) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	return kr.current, kr.keys[kr.current]
}

// Rotate introduces a new key and makes it the active signing key.
// The previous key is retained for verification of older signatures.
func (kr *KeyRotator) Rotate(newKey any, keyID string) {
	priv, ok := newKey.(ed25519.PrivateKey)
	if !ok {
		return
	}
	kr.mu.Lock()
	defer kr.mu.Unlock()
	kr.keys[keyID] = priv
	kr.current = keyID
}

// Verify checks a signature against the public key associated with keyID.
func (kr *KeyRotator) Verify(keyID string, msg, sig []byte) error {
	kr.mu.RLock()
	priv, ok := kr.keys[keyID]
	kr.mu.RUnlock()
	if !ok {
		return fmt.Errorf("key rotator: unknown keyID %q", keyID)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, msg, sig) {
		return fmt.Errorf("key rotator: signature verification failed for keyID %q", keyID)
	}
	return nil
}

// PublicKeys returns all public keys indexed by key ID.
func (kr *KeyRotator) PublicKeys() map[string]ed25519.PublicKey {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	out := make(map[string]ed25519.PublicKey, len(kr.keys))
	for id, priv := range kr.keys {
		out[id] = priv.Public().(ed25519.PublicKey)
	}
	return out
}

// JWKSHandler serves the rotator's public keys as a JWKS (JSON Web Key Set).
// GET /v1/keys → {"keys": [{"kid":"...","kty":"OKP","crv":"Ed25519","x":"..."}]}
type JWKSHandler struct {
	rotator *KeyRotator
}

// NewJWKSHandler creates a handler that serves public keys from the rotator.
func NewJWKSHandler(rotator *KeyRotator) *JWKSHandler {
	return &JWKSHandler{rotator: rotator}
}

type jwksKey struct {
	KID string `json:"kid"`
	KTY string `json:"kty"`
	CRV string `json:"crv"`
	X   string `json:"x"`
}

type jwksResponse struct {
	Keys []jwksKey `json:"keys"`
}

// ServeHTTP implements http.Handler for the JWKS endpoint.
func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	pubs := h.rotator.PublicKeys()
	resp := jwksResponse{Keys: make([]jwksKey, 0, len(pubs))}
	for kid, pub := range pubs {
		resp.Keys = append(resp.Keys, jwksKey{
			KID: kid,
			KTY: "OKP",
			CRV: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(pub),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// GenerateKeyRotator creates a KeyRotator with a fresh Ed25519 keypair.
func GenerateKeyRotator(keyID string) (*KeyRotator, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key rotator: %w", err)
	}
	return NewKeyRotator(keyID, priv), nil
}

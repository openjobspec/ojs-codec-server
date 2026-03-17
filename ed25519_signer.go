package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// Ed25519Signer is a real (non-stub) implementation of the Signer
// interface using crypto/ed25519. It maintains an in-memory key map
// keyed by `keyID` (mirrors KeyProvider semantics).
//
// The verify path is constant-time by virtue of crypto/ed25519's own
// implementation. The sign path errors out if `keyID` is unknown.
type Ed25519Signer struct {
	provider Ed25519KeyProvider
}

// Ed25519KeyProvider abstracts key storage so production deployments can
// plug in HSM/KMS backends without changing the Signer.
type Ed25519KeyProvider interface {
	PrivateKey(keyID string) (ed25519.PrivateKey, error)
	PublicKey(keyID string) (ed25519.PublicKey, error)
}

// NewEd25519Signer wraps a key provider as a Signer.
func NewEd25519Signer(provider Ed25519KeyProvider) *Ed25519Signer {
	return &Ed25519Signer{provider: provider}
}

func (s *Ed25519Signer) Algorithm() string { return SigAlgEd25519 }

func (s *Ed25519Signer) Sign(_ context.Context, keyID string, message []byte) ([]byte, error) {
	if err := validateKeyID(keyID); err != nil {
		return nil, err
	}
	priv, err := s.provider.PrivateKey(keyID)
	if err != nil {
		return nil, fmt.Errorf("ed25519 sign: %w", err)
	}
	return ed25519.Sign(priv, message), nil
}

func (s *Ed25519Signer) Verify(_ context.Context, keyID string, message, signature []byte) error {
	if err := validateKeyID(keyID); err != nil {
		return err
	}
	pub, err := s.provider.PublicKey(keyID)
	if err != nil {
		return fmt.Errorf("ed25519 verify: %w", err)
	}
	if !ed25519.Verify(pub, message, signature) {
		return fmt.Errorf("ed25519 verify: signature invalid")
	}
	return nil
}

// validateKeyID rejects empty, oversize, or filesystem-traversal keyIDs.
// See SECURITY-REVIEW-signer.md F-6.
func validateKeyID(keyID string) error {
	if keyID == "" {
		return fmt.Errorf("keyID is empty")
	}
	if len(keyID) > 256 {
		return fmt.Errorf("keyID exceeds 256 bytes")
	}
	for _, c := range keyID {
		if c == 0 || c == '/' || c == '\\' {
			return fmt.Errorf("keyID contains forbidden character %q", c)
		}
	}
	return nil
}

// MemoryKeyProvider is a simple in-memory implementation suitable for
// tests, design-partner P1 setups, and local development. Production
// deployments should use an HSM or KMS-backed implementation.
type MemoryKeyProvider struct {
	keys map[string]ed25519.PrivateKey
}

// NewMemoryKeyProvider returns an empty provider.
func NewMemoryKeyProvider() *MemoryKeyProvider {
	return &MemoryKeyProvider{keys: make(map[string]ed25519.PrivateKey)}
}

// Generate creates a fresh ed25519 keypair for the given keyID.
// Returns the public key (base64) for distribution.
func (p *MemoryKeyProvider) Generate(keyID string) (string, error) {
	if err := validateKeyID(keyID); err != nil {
		return "", err
	}
	if _, exists := p.keys[keyID]; exists {
		return "", fmt.Errorf("keyID %q already exists", keyID)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	p.keys[keyID] = priv
	return base64.StdEncoding.EncodeToString(pub), nil
}

// Import loads an existing private key (32-byte seed expanded form, or 64-byte private).
func (p *MemoryKeyProvider) Import(keyID string, priv ed25519.PrivateKey) error {
	if err := validateKeyID(keyID); err != nil {
		return err
	}
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("private key must be %d bytes", ed25519.PrivateKeySize)
	}
	p.keys[keyID] = priv
	return nil
}

func (p *MemoryKeyProvider) PrivateKey(keyID string) (ed25519.PrivateKey, error) {
	k, ok := p.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("unknown keyID: %s", keyID)
	}
	return k, nil
}

func (p *MemoryKeyProvider) PublicKey(keyID string) (ed25519.PublicKey, error) {
	k, ok := p.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("unknown keyID: %s", keyID)
	}
	return k.Public().(ed25519.PublicKey), nil
}

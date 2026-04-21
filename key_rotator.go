package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sync"
)

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

// GenerateKeyRotator creates a KeyRotator with a fresh Ed25519 keypair.
func GenerateKeyRotator(keyID string) (*KeyRotator, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key rotator: %w", err)
	}
	return NewKeyRotator(keyID, priv), nil
}

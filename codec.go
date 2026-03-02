package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"sync"
)

// KeyProvider supplies encryption keys for the codec.
type KeyProvider interface {
	GetKey(keyID string) ([]byte, error)
	CurrentKeyID() string
}

// MultiKeyProvider supports multiple named keys for key rotation.
// New encryptions use the current key; decryptions look up the key by ID.
type MultiKeyProvider struct {
	mu        sync.RWMutex
	keys      map[string][]byte
	currentID string
}

// NewMultiKeyProvider creates a provider with the given current key ID.
func NewMultiKeyProvider(currentID string) *MultiKeyProvider {
	return &MultiKeyProvider{
		keys:      make(map[string][]byte),
		currentID: currentID,
	}
}

// AddKey registers an AES-256 key. The key must be exactly 32 bytes.
func (p *MultiKeyProvider) AddKey(id string, key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("key %q must be 32 bytes for AES-256, got %d", id, len(key))
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keys[id] = make([]byte, 32)
	copy(p.keys[id], key)
	return nil
}

func (p *MultiKeyProvider) GetKey(keyID string) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	key, ok := p.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("unknown key ID: %s", keyID)
	}
	return key, nil
}

func (p *MultiKeyProvider) CurrentKeyID() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.currentID
}

// encrypt encrypts plaintext using AES-256-GCM.
// Returns: nonce (12 bytes) || ciphertext (N bytes) || GCM tag (16 bytes).
func encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Seal appends ciphertext + GCM tag to nonce
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// decrypt decrypts data produced by encrypt.
// Input format: nonce (12 bytes) || ciphertext || GCM tag (16 bytes).
func decrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize+gcm.Overhead() {
		return nil, fmt.Errorf("ciphertext too short: need at least %d bytes, got %d", nonceSize+gcm.Overhead(), len(data))
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

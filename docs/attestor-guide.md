# Attestor Plugin Guide

This guide explains how to write an **Attestor plugin** for the OJS
Codec Server. Attestors provide cryptographic proof that a job payload
was encrypted by a trusted entity and has not been tampered with.

## Overview

The OJS Codec Server encrypts/decrypts job payloads using AES-256-GCM.
An **Attestor** adds an additional trust layer by signing payloads
before encryption and verifying signatures after decryption.

```
┌──────────┐   sign    ┌───────────┐  encrypt   ┌──────────────┐
│ Producer │──────────▶│  Attestor │───────────▶│ Codec Server │
│          │           │  Plugin   │            │  (AES-256)   │
└──────────┘           └───────────┘            └──────┬───────┘
                                                       │
                                              encrypted + signed
                                                       │
┌──────────┐   verify  ┌───────────┐  decrypt   ┌──────▼───────┐
│ Consumer │◀──────────│  Attestor │◀───────────│ Codec Server │
│          │           │  Plugin   │            │              │
└──────────┘           └───────────┘            └──────────────┘
```

## The Attestor Interface

An Attestor must implement the following Go interface:

```go
// Attestor provides payload attestation for the codec server.
type Attestor interface {
    // Name returns a unique identifier for this attestor (e.g. "ed25519").
    Name() string

    // Sign produces a signature over the given payload. The returned
    // bytes are stored alongside the encrypted payload in the job
    // envelope as base64-encoded attestation metadata.
    Sign(payload []byte) (signature []byte, err error)

    // Verify checks that the signature is valid for the given payload.
    // Returns nil if valid, an error otherwise.
    Verify(payload []byte, signature []byte) error
}
```

## Step-by-Step: Ed25519 Attestor

The codec server ships with a built-in Ed25519 attestor. Here's how
it works — use it as a template for your own.

### 1. Implement the interface

```go
package myattestor

import (
    "crypto/ed25519"
    "errors"
)

type Ed25519Attestor struct {
    privKey ed25519.PrivateKey
    pubKey  ed25519.PublicKey
}

func New(privKey ed25519.PrivateKey) *Ed25519Attestor {
    return &Ed25519Attestor{
        privKey: privKey,
        pubKey:  privKey.Public().(ed25519.PublicKey),
    }
}

func (a *Ed25519Attestor) Name() string {
    return "ed25519"
}

func (a *Ed25519Attestor) Sign(payload []byte) ([]byte, error) {
    if a.privKey == nil {
        return nil, errors.New("ed25519: no private key configured")
    }
    return ed25519.Sign(a.privKey, payload), nil
}

func (a *Ed25519Attestor) Verify(payload, signature []byte) error {
    if len(signature) != ed25519.SignatureSize {
        return errors.New("ed25519: invalid signature length")
    }
    if !ed25519.Verify(a.pubKey, payload, signature) {
        return errors.New("ed25519: verification failed")
    }
    return nil
}
```

### 2. Register with the codec server

```go
package main

import (
    "crypto/ed25519"
    "crypto/rand"
    "log"

    "github.com/openjobspec/ojs-codec-server"
    "mycompany.com/myattestor"
)

func main() {
    // Generate or load your key pair.
    pub, priv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil {
        log.Fatal(err)
    }
    _ = pub // distribute public key to verifiers

    attestor := myattestor.New(priv)

    // Pass the attestor to the codec server configuration.
    server := codec.NewServer(codec.Config{
        Attestor: attestor,
        // ... other config ...
    })
    log.Fatal(server.ListenAndServe(":9090"))
}
```

### 3. Key management

| Concern | Recommendation |
|---------|---------------|
| Key generation | Use `crypto/ed25519.GenerateKey` with `crypto/rand.Reader` |
| Key storage | Store private keys in a secrets manager (Vault, AWS Secrets Manager, etc.) |
| Key rotation | Deploy new keys with a grace period; old keys should remain valid for verification during rollout |
| Key distribution | Public keys can be distributed via environment variables, config files, or a key server |

## Writing a Custom Attestor

### HMAC-SHA256 Example

```go
package hmacattestor

import (
    "crypto/hmac"
    "crypto/sha256"
    "errors"
)

type HMACAttestor struct {
    secret []byte
}

func New(secret []byte) *HMACAttestor {
    return &HMACAttestor{secret: secret}
}

func (a *HMACAttestor) Name() string {
    return "hmac-sha256"
}

func (a *HMACAttestor) Sign(payload []byte) ([]byte, error) {
    mac := hmac.New(sha256.New, a.secret)
    mac.Write(payload)
    return mac.Sum(nil), nil
}

func (a *HMACAttestor) Verify(payload, signature []byte) error {
    mac := hmac.New(sha256.New, a.secret)
    mac.Write(payload)
    expected := mac.Sum(nil)
    if !hmac.Equal(signature, expected) {
        return errors.New("hmac-sha256: verification failed")
    }
    return nil
}
```

## Testing Your Attestor

Every attestor should pass these invariants:

```go
func TestAttestor(t *testing.T, a Attestor) {
    payload := []byte(`{"type":"test","args":[1,2,3]}`)

    // 1. Sign must succeed.
    sig, err := a.Sign(payload)
    if err != nil {
        t.Fatalf("Sign: %v", err)
    }

    // 2. Verify must succeed with correct signature.
    if err := a.Verify(payload, sig); err != nil {
        t.Fatalf("Verify: %v", err)
    }

    // 3. Verify must fail with tampered payload.
    tampered := append([]byte{}, payload...)
    tampered[0] = 'X'
    if err := a.Verify(tampered, sig); err == nil {
        t.Error("Verify should fail on tampered payload")
    }

    // 4. Verify must fail with wrong signature.
    wrongSig := append([]byte{}, sig...)
    wrongSig[0] ^= 0xFF
    if err := a.Verify(payload, wrongSig); err == nil {
        t.Error("Verify should fail on wrong signature")
    }
}
```

## Envelope Wire Format

When an attestor is configured, the encrypted payload in the job
envelope includes attestation metadata:

```json
{
  "type": "email.send",
  "args": ["<encrypted>"],
  "meta": {
    "ojs.codec": {
      "algorithm": "AES-256-GCM",
      "attestor": "ed25519",
      "signature": "<base64-encoded-signature>"
    }
  }
}
```

## Security Considerations

1. **Never log private keys or secrets** in production.
2. **Use constant-time comparison** for signature verification
   (`hmac.Equal`, `ed25519.Verify` — not `bytes.Equal`).
3. **Sign before encrypt** — the attestor signs the plaintext, then
   the codec encrypts. This ensures the signature covers the actual
   payload, not the ciphertext.
4. **Rotate keys regularly** — support overlapping validity windows
   during rotation.

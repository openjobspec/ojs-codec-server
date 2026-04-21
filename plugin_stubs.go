package main

import (
	"context"
	"fmt"
)

// ----- Stub implementations for early integration testing -----
// These are intentionally minimal and NOT cryptographically secure on their own;
// real Ed25519/ML-DSA/Nitro implementations land in M1 P1 Prototype.

// stubSigner deterministically returns "sig:<alg>:<keyID>:<len>" — useful only
// for wiring/contract tests. Replace before any non-test use.
type stubSigner struct{ alg string }

// NewStubSigner returns a placeholder signer for the given algorithm.
// It is exported so tests in dependent SDKs can exercise the contract end-to-end
// before real crypto is wired in. Logs a startup warning when used.
func NewStubSigner(algorithm string) Signer { return &stubSigner{alg: algorithm} }

func (s *stubSigner) Algorithm() string { return s.alg }

func (s *stubSigner) Sign(_ context.Context, keyID string, message []byte) ([]byte, error) {
	return []byte(fmt.Sprintf("stub-sig:%s:%s:%d", s.alg, keyID, len(message))), nil
}

func (s *stubSigner) Verify(_ context.Context, keyID string, message, signature []byte) error {
	want := fmt.Sprintf("stub-sig:%s:%s:%d", s.alg, keyID, len(message))
	if string(signature) != want {
		return fmt.Errorf("stub signature mismatch")
	}
	return nil
}

// stubAttestor returns a placeholder attestation envelope.
type stubAttestor struct{ kind string }

// NewStubAttestor returns a placeholder attestor for the given environment type.
func NewStubAttestor(kind string) Attestor { return &stubAttestor{kind: kind} }

func (a *stubAttestor) Type() string { return a.kind }

func (a *stubAttestor) Attest(_ context.Context, payload []byte) ([]byte, error) {
	return []byte(fmt.Sprintf("stub-attest:%s:%d", a.kind, len(payload))), nil
}

func (a *stubAttestor) Verify(_ context.Context, payload, document []byte) error {
	want := fmt.Sprintf("stub-attest:%s:%d", a.kind, len(payload))
	if string(document) != want {
		return fmt.Errorf("stub attestation mismatch")
	}
	return nil
}

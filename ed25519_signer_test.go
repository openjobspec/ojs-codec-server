package main

import (
	"context"
	"testing"
)

func TestEd25519SignerRoundTrip(t *testing.T) {
	kp := NewMemoryKeyProvider()
	if _, err := kp.Generate("backend-postgres-2026"); err != nil {
		t.Fatal(err)
	}
	s := NewEd25519Signer(kp)

	msg := []byte("conformance report sha256:deadbeef...")
	sig, err := s.Sign(context.Background(), "backend-postgres-2026", msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(sig) != 64 {
		t.Errorf("expected 64-byte signature, got %d", len(sig))
	}
	if err := s.Verify(context.Background(), "backend-postgres-2026", msg, sig); err != nil {
		t.Errorf("verify: %v", err)
	}
	if err := s.Verify(context.Background(), "backend-postgres-2026", []byte("tampered"), sig); err == nil {
		t.Error("verify of tampered message must fail")
	}
}

func TestEd25519SignerUnknownKey(t *testing.T) {
	s := NewEd25519Signer(NewMemoryKeyProvider())
	if _, err := s.Sign(context.Background(), "ghost", []byte("x")); err == nil {
		t.Error("sign with unknown keyID must fail")
	}
}

func TestEd25519SignerKeyIDValidation(t *testing.T) {
	s := NewEd25519Signer(NewMemoryKeyProvider())
	cases := []string{
		"",
		"../etc/passwd",
		"a/b",
		"a\x00b",
	}
	for _, kid := range cases {
		if _, err := s.Sign(context.Background(), kid, []byte("x")); err == nil {
			t.Errorf("expected validation error for keyID %q", kid)
		}
	}
}

func TestEd25519SignerRegistersInRegistry(t *testing.T) {
	r := NewRegistry()
	kp := NewMemoryKeyProvider()
	_, _ = kp.Generate("k1")
	if err := r.Register(&Plugin{Name: "ed25519-real", Signer: NewEd25519Signer(kp)}); err != nil {
		t.Fatalf("register: %v", err)
	}
	// Cannot register the stub afterward — both claim ed25519. This is the
	// F-4 hardening at work, end-to-end.
	if err := r.Register(&Plugin{Name: "ed25519-stub", Signer: NewStubSigner(SigAlgEd25519)}); err == nil {
		t.Error("expected algorithm collision rejection")
	}
}

func TestMemoryKeyProviderDuplicate(t *testing.T) {
	kp := NewMemoryKeyProvider()
	if _, err := kp.Generate("k1"); err != nil {
		t.Fatal(err)
	}
	if _, err := kp.Generate("k1"); err == nil {
		t.Error("Generate must reject duplicate keyID")
	}
}

package main

import (
	"context"
	"testing"
)

func TestRegistryRegisterAndLookup(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(&Plugin{
		Name:     "ed25519-stub",
		Signer:   NewStubSigner(SigAlgEd25519),
		Attestor: NewStubAttestor(AttestPQCOnly),
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if got, ok := r.Get("ed25519-stub"); !ok || got.Signer == nil {
		t.Fatalf("Get returned %v, %v", got, ok)
	}
	if r.Signer(SigAlgEd25519) == nil {
		t.Error("signer lookup by algorithm failed")
	}
	if r.Attestor(AttestPQCOnly) == nil {
		t.Error("attestor lookup by type failed")
	}
	names := r.Names()
	if len(names) != 1 || names[0] != "ed25519-stub" {
		t.Errorf("unexpected names: %v", names)
	}
}

func TestRegistryRejectsDuplicate(t *testing.T) {
	r := NewRegistry()
	p := &Plugin{Name: "dup", Signer: NewStubSigner(SigAlgEd25519)}
	if err := r.Register(p); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(p); err == nil {
		t.Error("expected duplicate registration to fail")
	}
}

func TestRegistryRejectsEmptyPlugin(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(nil); err == nil {
		t.Error("expected nil plugin to fail")
	}
	if err := r.Register(&Plugin{Name: "x"}); err == nil {
		t.Error("expected plugin with no signer/attestor to fail")
	}
}

func TestStubSignerRoundTrip(t *testing.T) {
	s := NewStubSigner(SigAlgMLDSA65)
	msg := []byte("hello")
	sig, err := s.Sign(context.Background(), "k1", msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(context.Background(), "k1", msg, sig); err != nil {
		t.Errorf("verify failed: %v", err)
	}
	if err := s.Verify(context.Background(), "k1", []byte("tampered"), sig); err == nil {
		t.Error("expected verify failure on tampered message")
	}
}

func TestStubAttestorRoundTrip(t *testing.T) {
	a := NewStubAttestor(AttestAWSNitro)
	payload := []byte("digest")
	doc, err := a.Attest(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Verify(context.Background(), payload, doc); err != nil {
		t.Errorf("attest verify failed: %v", err)
	}
	if err := a.Verify(context.Background(), []byte("other"), doc); err == nil {
		t.Error("expected verify failure on different payload")
	}
}

func TestKeyProviderUnaffected(t *testing.T) {
	// Existing AES-256-GCM path must remain intact alongside new plugin types.
	kp := NewMultiKeyProvider("k1")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if err := kp.AddKey("k1", key); err != nil {
		t.Fatal(err)
	}
	ct, err := encrypt(key, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := decrypt(key, ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "payload" {
		t.Errorf("aes round-trip broken: %q", pt)
	}
}

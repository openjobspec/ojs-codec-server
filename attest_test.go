package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAttestPipeline(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rotator := NewKeyRotator("key-1", priv)
	signer := NewEd25519Signer(&testKeyProvider{priv: priv, keyID: "key-1"})
	attestor := NewStubAttestor(AttestPQCOnly)

	pipeline := NewAttestPipeline(signer, attestor, rotator)

	payload := []byte("job-args-hash:sha256:deadbeef")
	env, err := pipeline.Run(context.Background(), payload, "us-east-1")
	if err != nil {
		t.Fatalf("pipeline run: %v", err)
	}
	if env.KeyID != "key-1" {
		t.Errorf("expected keyID key-1, got %s", env.KeyID)
	}
	if env.Jurisdiction != "us-east-1" {
		t.Errorf("expected jurisdiction us-east-1, got %s", env.Jurisdiction)
	}
	if len(env.Signature) == 0 {
		t.Error("expected non-empty signature")
	}
	if len(env.Quote) == 0 {
		t.Error("expected non-empty quote")
	}
	if env.IssuedAt == "" {
		t.Error("expected non-empty issuedAt")
	}
}

func TestKeyRotator_Rotate(t *testing.T) {
	_, priv1, _ := ed25519.GenerateKey(rand.Reader)
	rotator := NewKeyRotator("key-1", priv1)

	kid, _ := rotator.Current()
	if kid != "key-1" {
		t.Fatalf("expected current key-1, got %s", kid)
	}

	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	rotator.Rotate(priv2, "key-2")

	kid, _ = rotator.Current()
	if kid != "key-2" {
		t.Errorf("expected current key-2 after rotation, got %s", kid)
	}

	// Old key still available for verification.
	pubs := rotator.PublicKeys()
	if len(pubs) != 2 {
		t.Errorf("expected 2 public keys, got %d", len(pubs))
	}
}

func TestKeyRotator_VerifyCurrent(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	rotator := NewKeyRotator("key-1", priv)

	msg := []byte("test message to verify")
	sig := ed25519.Sign(priv, msg)

	if err := rotator.Verify("key-1", msg, sig); err != nil {
		t.Fatalf("verify current key: %v", err)
	}

	// Tampered message must fail.
	if err := rotator.Verify("key-1", []byte("tampered"), sig); err == nil {
		t.Error("verify of tampered message must fail")
	}

	// Unknown key must fail.
	if err := rotator.Verify("ghost", msg, sig); err == nil {
		t.Error("verify with unknown keyID must fail")
	}
}

func TestJWKSHandler(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	rotator := NewKeyRotator("jwks-key-1", priv)
	handler := NewJWKSHandler(rotator)

	req := httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	// Verify Content-Type header
	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}

	var resp jwksResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal JWKS: %v", err)
	}

	// Verify JWKS JSON structure
	if len(resp.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(resp.Keys))
	}
	k := resp.Keys[0]

	// Verify key type is OKP for Ed25519
	if k.KTY != "OKP" {
		t.Errorf("expected kty OKP, got %s", k.KTY)
	}
	if k.CRV != "Ed25519" {
		t.Errorf("expected crv Ed25519, got %s", k.CRV)
	}

	// Verify key ID matches rotator's current key
	currentKeyID, _ := rotator.Current()
	if k.KID != currentKeyID {
		t.Errorf("expected kid %q (rotator current), got %q", currentKeyID, k.KID)
	}
	if k.KID != "jwks-key-1" {
		t.Errorf("expected kid jwks-key-1, got %s", k.KID)
	}

	// Verify public key data is present and valid base64url
	if k.X == "" {
		t.Error("expected non-empty x (public key)")
	}

	// POST must be rejected.
	req2 := httptest.NewRequest(http.MethodPost, "/v1/keys", nil)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST, got %d", rr2.Code)
	}
}

func TestJWKSHandler_AfterRotation(t *testing.T) {
	_, priv1, _ := ed25519.GenerateKey(rand.Reader)
	rotator := NewKeyRotator("key-a", priv1)

	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	rotator.Rotate(priv2, "key-b")

	handler := NewJWKSHandler(rotator)
	req := httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp jwksResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal JWKS: %v", err)
	}

	if len(resp.Keys) != 2 {
		t.Fatalf("expected 2 keys after rotation, got %d", len(resp.Keys))
	}

	kidSet := map[string]bool{}
	for _, k := range resp.Keys {
		kidSet[k.KID] = true
		if k.KTY != "OKP" {
			t.Errorf("key %s: expected kty OKP, got %s", k.KID, k.KTY)
		}
		if k.CRV != "Ed25519" {
			t.Errorf("key %s: expected crv Ed25519, got %s", k.KID, k.CRV)
		}
	}
	if !kidSet["key-a"] {
		t.Error("expected key-a in JWKS after rotation")
	}
	if !kidSet["key-b"] {
		t.Error("expected key-b in JWKS after rotation")
	}

	// Verify current key is key-b
	currentKeyID, _ := rotator.Current()
	if currentKeyID != "key-b" {
		t.Errorf("expected current key key-b, got %s", currentKeyID)
	}
}

func TestJWKSHandler_ContentType(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	rotator := NewKeyRotator("ct-key", priv)
	handler := NewJWKSHandler(rotator)

	req := httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type: want application/json, got %q", ct)
	}
}

func TestJWKSHandler_ValidJWKSStructure(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	rotator := NewKeyRotator("struct-key", priv)
	handler := NewJWKSHandler(rotator)

	req := httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Verify the raw JSON has the "keys" array
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal raw JSON: %v", err)
	}
	if _, ok := raw["keys"]; !ok {
		t.Error("JWKS response missing 'keys' field")
	}

	// Verify each key has all required JWK fields
	var resp jwksResponse
	json.Unmarshal(rr.Body.Bytes(), &resp)
	for _, k := range resp.Keys {
		if k.KID == "" {
			t.Error("JWK missing kid field")
		}
		if k.KTY == "" {
			t.Error("JWK missing kty field")
		}
		if k.CRV == "" {
			t.Error("JWK missing crv field")
		}
		if k.X == "" {
			t.Error("JWK missing x field")
		}
	}
}

func TestAttestPipeline_NilAttestor(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	rotator := NewKeyRotator("key-1", priv)
	signer := NewEd25519Signer(&testKeyProvider{priv: priv, keyID: "key-1"})

	pipeline := NewAttestPipeline(signer, nil, rotator)

	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic when attestor is nil")
		}
	}()

	_, _ = pipeline.Run(context.Background(), []byte("test"), "us-east-1")
}

func TestKeyRotator_VerifyOldKey(t *testing.T) {
	_, priv1, _ := ed25519.GenerateKey(rand.Reader)
	rotator := NewKeyRotator("key-1", priv1)

	// Sign with original key
	msg := []byte("original message")
	sig := ed25519.Sign(priv1, msg)

	// Rotate to a new key
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	rotator.Rotate(priv2, "key-2")

	// Old key should still verify old signatures
	if err := rotator.Verify("key-1", msg, sig); err != nil {
		t.Fatalf("old key should still verify old signatures: %v", err)
	}

	// New key should work for new signatures
	msg2 := []byte("new message")
	sig2 := ed25519.Sign(priv2, msg2)
	if err := rotator.Verify("key-2", msg2, sig2); err != nil {
		t.Fatalf("new key should verify new signatures: %v", err)
	}
}

func TestKeyRotator_RejectUnknownKeyID(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	rotator := NewKeyRotator("key-1", priv)

	msg := []byte("test message")
	sig := ed25519.Sign(priv, msg)

	err := rotator.Verify("non-existent-key", msg, sig)
	if err == nil {
		t.Error("expected error for unknown keyID")
	}
	if !strings.Contains(err.Error(), "unknown keyID") {
		t.Errorf("error should mention unknown keyID, got: %v", err)
	}
}

func TestJWKSHandler_KeyFields(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	rotator := NewKeyRotator("field-test-key", priv)
	handler := NewJWKSHandler(rotator)

	req := httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp jwksResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal JWKS: %v", err)
	}

	if len(resp.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(resp.Keys))
	}

	k := resp.Keys[0]
	if k.KID != "field-test-key" {
		t.Errorf("kid = %q, want field-test-key", k.KID)
	}
	if k.KTY != "OKP" {
		t.Errorf("kty = %q, want OKP", k.KTY)
	}
	if k.CRV != "Ed25519" {
		t.Errorf("crv = %q, want Ed25519", k.CRV)
	}
	if k.X == "" {
		t.Error("x field should be non-empty")
	}
}

// testKeyProvider is a minimal Ed25519KeyProvider for pipeline tests.
type testKeyProvider struct {
	priv  ed25519.PrivateKey
	keyID string
}

func (p *testKeyProvider) PrivateKey(keyID string) (ed25519.PrivateKey, error) {
	if keyID != p.keyID {
		return nil, fmt.Errorf("unknown keyID: %s", keyID)
	}
	return p.priv, nil
}

func (p *testKeyProvider) PublicKey(keyID string) (ed25519.PublicKey, error) {
	if keyID != p.keyID {
		return nil, fmt.Errorf("unknown keyID: %s", keyID)
	}
	return p.priv.Public().(ed25519.PublicKey), nil
}

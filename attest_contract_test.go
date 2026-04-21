package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAttestPipelineRunByteAndErrorContracts(t *testing.T) {
	priv := deterministicPrivateKey()
	rotator := NewKeyRotator("active-key", priv)
	signer := &recordingSigner{signature: []byte("signature-bytes")}
	attestor := &recordingAttestor{document: []byte("quote-bytes")}
	pipeline := NewAttestPipeline(signer, attestor, rotator)
	payload := []byte("payload-bytes")
	digest := sha256.Sum256(payload)

	env, err := pipeline.Run(context.Background(), payload, "eu-west")
	if err != nil {
		t.Fatal(err)
	}
	if signer.keyID != "active-key" {
		t.Errorf("signer key ID = %q", signer.keyID)
	}
	if !bytes.Equal(signer.message, digest[:]) {
		t.Errorf("signer message = %x, want digest %x", signer.message, digest)
	}
	if !bytes.Equal(attestor.payload, digest[:]) {
		t.Errorf("attestor payload = %x, want digest %x", attestor.payload, digest)
	}
	if !bytes.Equal(env.Payload, payload) ||
		!bytes.Equal(env.Signature, []byte("signature-bytes")) ||
		!bytes.Equal(env.Quote, []byte("quote-bytes")) {
		t.Errorf("unexpected envelope bytes: %#v", env)
	}
	if env.KeyID != "active-key" || env.Jurisdiction != "eu-west" {
		t.Errorf("unexpected envelope metadata: %#v", env)
	}
	issuedAt, err := time.Parse(time.RFC3339, env.IssuedAt)
	if err != nil {
		t.Fatalf("IssuedAt = %q: %v", env.IssuedAt, err)
	}
	if issuedAt.Location() != time.UTC {
		t.Errorf("IssuedAt location = %v, want UTC", issuedAt.Location())
	}

	signer.signErr = errors.New("sign failed")
	attestor.calls = 0
	_, err = pipeline.Run(context.Background(), payload, "eu-west")
	if got := errorString(err); got != "attest pipeline: sign: sign failed" {
		t.Fatalf("sign error = %q", got)
	}
	if attestor.calls != 0 {
		t.Fatalf("attestor called %d times after sign failure", attestor.calls)
	}

	signer.signErr = nil
	attestor.attestErr = errors.New("attest failed")
	_, err = pipeline.Run(context.Background(), payload, "eu-west")
	if got := errorString(err); got != "attest pipeline: attest: attest failed" {
		t.Fatalf("attest error = %q", got)
	}
}

func TestAttestPipelineVerifyByteAndErrorContracts(t *testing.T) {
	priv := deterministicPrivateKey()
	rotator := NewKeyRotator("verify-key", priv)
	attestor := &recordingAttestor{}
	pipeline := NewAttestPipeline(&recordingSigner{}, attestor, rotator)
	payload := []byte("verify-payload")
	digest := sha256.Sum256(payload)
	env := &AttestEnvelope{
		Payload:   payload,
		Signature: ed25519.Sign(priv, digest[:]),
		KeyID:     "verify-key",
		Quote:     []byte("quote"),
	}

	if err := pipeline.Verify(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(attestor.payload, digest[:]) || !bytes.Equal(attestor.document, env.Quote) {
		t.Errorf("verify attestor bytes = %x / %x", attestor.payload, attestor.document)
	}

	attestor.calls = 0
	env.KeyID = "missing"
	err := pipeline.Verify(context.Background(), env)
	if got := errorString(err); got != `attest pipeline: verify signature: key rotator: unknown keyID "missing"` {
		t.Fatalf("unknown-key error = %q", got)
	}
	if attestor.calls != 0 {
		t.Fatalf("attestor called %d times after signature failure", attestor.calls)
	}

	env.KeyID = "verify-key"
	env.Signature = make([]byte, ed25519.SignatureSize)
	err = pipeline.Verify(context.Background(), env)
	if got := errorString(err); got != `attest pipeline: verify signature: key rotator: signature verification failed for keyID "verify-key"` {
		t.Fatalf("signature error = %q", got)
	}

	env.Signature = ed25519.Sign(priv, digest[:])
	attestor.verifyErr = errors.New("quote failed")
	err = pipeline.Verify(context.Background(), env)
	if got := errorString(err); got != "attest pipeline: verify quote: quote failed" {
		t.Fatalf("quote error = %q", got)
	}
}

func TestAttestEnvelopeJSONContract(t *testing.T) {
	raw, err := json.Marshal(AttestEnvelope{
		Payload:      []byte{0x01, 0x02},
		Signature:    []byte{0x03, 0x04},
		KeyID:        "key",
		Quote:        []byte{0x05, 0x06},
		Jurisdiction: "region",
		IssuedAt:     "2026-08-03T04:36:08Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"payload":"AQI=","signature":"AwQ=","key_id":"key","quote":"BQY=","jurisdiction":"region","issued_at":"2026-08-03T04:36:08Z"}`
	if string(raw) != want {
		t.Fatalf("envelope JSON = %s, want %s", raw, want)
	}
}

func TestKeyRotatorCustodyContracts(t *testing.T) {
	priv1 := deterministicPrivateKey()
	seed2 := bytes.Repeat([]byte{0x7f}, ed25519.SeedSize)
	priv2 := ed25519.NewKeyFromSeed(seed2)
	rotator := NewKeyRotator("key-1", priv1)

	rotator.Rotate("not-an-ed25519-key", "ignored")
	if keyID, key := rotator.Current(); keyID != "key-1" || !bytes.Equal(key.(ed25519.PrivateKey), priv1) {
		t.Fatalf("invalid rotation changed current key: %q %T", keyID, key)
	}

	rotator.Rotate(priv2, "key-1")
	keyID, key := rotator.Current()
	if keyID != "key-1" || !bytes.Equal(key.(ed25519.PrivateKey), priv2) {
		t.Fatalf("same-ID rotation did not replace key: %q", keyID)
	}
	if got := len(rotator.PublicKeys()); got != 1 {
		t.Fatalf("public key count = %d, want 1", got)
	}

	publicKeys := rotator.PublicKeys()
	delete(publicKeys, "key-1")
	if got := len(rotator.PublicKeys()); got != 1 {
		t.Fatalf("mutating returned map changed custody; count = %d", got)
	}
}

func TestJWKSExactHTTPContract(t *testing.T) {
	priv := deterministicPrivateKey()
	rotator := NewKeyRotator("key-a", priv)
	handler := NewJWKSHandler(rotator)
	publicKey := priv.Public().(ed25519.PublicKey)

	req := httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	wantBody := `{"keys":[{"kid":"key-a","kty":"OKP","crv":"Ed25519","x":"` +
		base64.RawURLEncoding.EncodeToString(publicKey) +
		`"}]}` + "\n"
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := rr.Body.String(); got != wantBody {
		t.Fatalf("body = %q, want %q", got, wantBody)
	}

	req = httptest.NewRequest(http.MethodHead, "/v1/keys", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("HEAD status = %d, want 405", rr.Code)
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("HEAD Content-Type = %q", got)
	}
	if got := rr.Body.String(); got != `{"error":"method not allowed"}`+"\n" {
		t.Fatalf("HEAD body = %q", got)
	}
}

func deterministicPrivateKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

type recordingSigner struct {
	keyID     string
	message   []byte
	signature []byte
	signErr   error
}

func (s *recordingSigner) Algorithm() string {
	return SigAlgEd25519
}

func (s *recordingSigner) Sign(_ context.Context, keyID string, message []byte) ([]byte, error) {
	s.keyID = keyID
	s.message = append([]byte(nil), message...)
	return s.signature, s.signErr
}

func (s *recordingSigner) Verify(context.Context, string, []byte, []byte) error {
	return nil
}

type recordingAttestor struct {
	payload   []byte
	document  []byte
	calls     int
	attestErr error
	verifyErr error
}

func (a *recordingAttestor) Type() string {
	return AttestPQCOnly
}

func (a *recordingAttestor) Attest(_ context.Context, payload []byte) ([]byte, error) {
	a.calls++
	a.payload = append([]byte(nil), payload...)
	return a.document, a.attestErr
}

func (a *recordingAttestor) Verify(_ context.Context, payload, document []byte) error {
	a.calls++
	a.payload = append([]byte(nil), payload...)
	a.document = append([]byte(nil), document...)
	return a.verifyErr
}

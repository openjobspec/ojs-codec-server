package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testProvider(t *testing.T) *MultiKeyProvider {
	t.Helper()
	// Deterministic 32-byte test key
	key := []byte("01234567890123456789012345678901")
	p := NewMultiKeyProvider("test-key")
	if err := p.AddKey("test-key", key); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	plaintext := []byte("hello, world!")

	ciphertext, err := encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext should differ from plaintext")
	}

	got, err := decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("got %q, want %q", got, plaintext)
	}
}

func TestEncryptNonceUniqueness(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	plaintext := []byte("same data")

	c1, _ := encrypt(key, plaintext)
	c2, _ := encrypt(key, plaintext)

	if bytes.Equal(c1, c2) {
		t.Fatal("two encryptions of the same data should produce different ciphertexts")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1 := []byte("01234567890123456789012345678901")
	key2 := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")

	ciphertext, _ := encrypt(key1, []byte("secret"))
	_, err := decrypt(key2, ciphertext)
	if err == nil {
		t.Fatal("expected decryption to fail with wrong key")
	}
}

func TestDecryptTooShort(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	_, err := decrypt(key, []byte("short"))
	if err == nil {
		t.Fatal("expected error for short ciphertext")
	}
}

func TestMultiKeyProvider(t *testing.T) {
	p := NewMultiKeyProvider("key-1")
	key1 := []byte("01234567890123456789012345678901")
	key2 := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")

	if err := p.AddKey("key-1", key1); err != nil {
		t.Fatal(err)
	}
	if err := p.AddKey("key-2", key2); err != nil {
		t.Fatal(err)
	}

	if p.CurrentKeyID() != "key-1" {
		t.Fatalf("got current key ID %q, want %q", p.CurrentKeyID(), "key-1")
	}

	got, err := p.GetKey("key-2")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, key2) {
		t.Fatal("wrong key returned")
	}

	_, err = p.GetKey("nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
}

func TestMultiKeyProviderBadKeySize(t *testing.T) {
	p := NewMultiKeyProvider("k")
	err := p.AddKey("k", []byte("too-short"))
	if err == nil {
		t.Fatal("expected error for wrong key size")
	}
}

func TestHandleEncodeAndDecode(t *testing.T) {
	provider := testProvider(t)

	original := []byte(`{"customer_id":"cust_123","card":"4111111111111111"}`)
	b64 := base64.StdEncoding.EncodeToString(original)

	// Encode
	encReq := CodecRequest{Payloads: []Payload{{Data: b64}}}
	body, _ := json.Marshal(encReq)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/codec/encode", bytes.NewReader(body))
	handleEncode(provider)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("encode: got status %d, body: %s", rr.Code, rr.Body.String())
	}

	var encResp CodecResponse
	if err := json.NewDecoder(rr.Body).Decode(&encResp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(encResp.Payloads) != 1 {
		t.Fatalf("expected 1 payload, got %d", len(encResp.Payloads))
	}
	if encResp.Payloads[0].Metadata[metaCodec] != codecName {
		t.Fatalf("missing codec metadata")
	}
	if encResp.Payloads[0].Metadata[metaKeyID] != "test-key" {
		t.Fatalf("missing key ID metadata")
	}

	// Decode
	decReq := CodecRequest{Payloads: encResp.Payloads}
	body, _ = json.Marshal(decReq)

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/codec/decode", bytes.NewReader(body))
	handleDecode(provider)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("decode: got status %d, body: %s", rr.Code, rr.Body.String())
	}

	var decResp CodecResponse
	if err := json.NewDecoder(rr.Body).Decode(&decResp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(decResp.Payloads) != 1 {
		t.Fatalf("expected 1 payload, got %d", len(decResp.Payloads))
	}

	decoded, err := base64.StdEncoding.DecodeString(decResp.Payloads[0].Data)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	if !bytes.Equal(decoded, original) {
		t.Fatalf("round-trip failed: got %q, want %q", decoded, original)
	}
}

func TestHandleEncodeMultiplePayloads(t *testing.T) {
	provider := testProvider(t)

	payloads := []Payload{
		{Data: base64.StdEncoding.EncodeToString([]byte("payload-1"))},
		{Data: base64.StdEncoding.EncodeToString([]byte("payload-2"))},
		{Data: base64.StdEncoding.EncodeToString([]byte("payload-3"))},
	}
	body, _ := json.Marshal(CodecRequest{Payloads: payloads})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/codec/encode", bytes.NewReader(body))
	handleEncode(provider)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d", rr.Code)
	}

	var resp CodecResponse
	json.NewDecoder(rr.Body).Decode(&resp)
	if len(resp.Payloads) != 3 {
		t.Fatalf("expected 3 payloads, got %d", len(resp.Payloads))
	}
}

func TestHandleDecodePassthrough(t *testing.T) {
	provider := testProvider(t)

	// Payload without ojs_codec metadata should pass through
	payloads := []Payload{
		{Data: base64.StdEncoding.EncodeToString([]byte("plain data"))},
	}
	body, _ := json.Marshal(CodecRequest{Payloads: payloads})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/codec/decode", bytes.NewReader(body))
	handleDecode(provider)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, body: %s", rr.Code, rr.Body.String())
	}

	var resp CodecResponse
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Payloads[0].Data != payloads[0].Data {
		t.Fatal("unencrypted payload should pass through unchanged")
	}
}

func TestHandleEncodeInvalidJSON(t *testing.T) {
	provider := testProvider(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/codec/encode", bytes.NewReader([]byte("not json")))
	handleEncode(provider)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestHandleEncodeEmptyPayloads(t *testing.T) {
	provider := testProvider(t)
	body, _ := json.Marshal(CodecRequest{Payloads: []Payload{}})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/codec/encode", bytes.NewReader(body))
	handleEncode(provider)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestHandleEncodeMethodNotAllowed(t *testing.T) {
	provider := testProvider(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/codec/encode", nil)
	handleEncode(provider)(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

func TestHandleDecodeUnknownKeyID(t *testing.T) {
	provider := testProvider(t)
	payloads := []Payload{{
		Data: base64.StdEncoding.EncodeToString([]byte("data")),
		Metadata: map[string]string{
			metaCodec: codecName,
			metaKeyID: "nonexistent-key",
		},
	}}
	body, _ := json.Marshal(CodecRequest{Payloads: payloads})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/codec/decode", bytes.NewReader(body))
	handleDecode(provider)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestHandleDecodeMissingKeyID(t *testing.T) {
	provider := testProvider(t)
	payloads := []Payload{{
		Data: base64.StdEncoding.EncodeToString([]byte("data")),
		Metadata: map[string]string{
			metaCodec: codecName,
		},
	}}
	body, _ := json.Marshal(CodecRequest{Payloads: payloads})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/codec/decode", bytes.NewReader(body))
	handleDecode(provider)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestHandleDecodeUnsupportedCodec(t *testing.T) {
	provider := testProvider(t)
	payloads := []Payload{{
		Data: base64.StdEncoding.EncodeToString([]byte("data")),
		Metadata: map[string]string{
			metaCodec: "chacha20-poly1305",
			metaKeyID: "test-key",
		},
	}}
	body, _ := json.Marshal(CodecRequest{Payloads: payloads})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/codec/decode", bytes.NewReader(body))
	handleDecode(provider)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestHandleHealth(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	handleHealth(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp map[string]string
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Fatalf("expected ok, got %q", resp["status"])
	}
}

func TestCORSMiddleware(t *testing.T) {
	handler := corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Preflight
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodOptions, "/codec/decode", nil)
	req.Header.Set("Origin", "http://dashboard.example.com")
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("preflight: expected 204, got %d", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "http://dashboard.example.com" {
		t.Fatalf("CORS origin: got %q", got)
	}

	// Normal request
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/codec/encode", nil)
	req.Header.Set("Origin", "http://other.example.com")
	handler.ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "http://other.example.com" {
		t.Fatalf("CORS origin: got %q", got)
	}
}

package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
)

// JWKSHandler serves the rotator's public keys as a JWKS (JSON Web Key Set).
// GET /v1/keys → {"keys": [{"kid":"...","kty":"OKP","crv":"Ed25519","x":"..."}]}
type JWKSHandler struct {
	rotator *KeyRotator
}

// NewJWKSHandler creates a handler that serves public keys from the rotator.
func NewJWKSHandler(rotator *KeyRotator) *JWKSHandler {
	return &JWKSHandler{rotator: rotator}
}

type jwksKey struct {
	KID string `json:"kid"`
	KTY string `json:"kty"`
	CRV string `json:"crv"`
	X   string `json:"x"`
}

type jwksResponse struct {
	Keys []jwksKey `json:"keys"`
}

// ServeHTTP implements http.Handler for the JWKS endpoint.
func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	pubs := h.rotator.PublicKeys()
	resp := jwksResponse{Keys: make([]jwksKey, 0, len(pubs))}
	for kid, pub := range pubs {
		resp.Keys = append(resp.Keys, jwksKey{
			KID: kid,
			KTY: "OKP",
			CRV: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(pub),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

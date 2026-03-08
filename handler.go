package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
)

// Payload is a single item in the Codec Server wire format.
type Payload struct {
	Data     string            `json:"data"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// CodecRequest is the request body for /codec/encode and /codec/decode.
type CodecRequest struct {
	Payloads []Payload `json:"payloads"`
}

// CodecResponse is the response body for /codec/encode and /codec/decode.
type CodecResponse struct {
	Payloads []Payload `json:"payloads"`
}

const (
	metaCodec = "ojs_codec"
	metaKeyID = "ojs_key_id"
	codecName = "aes-256-gcm"
)

// handleEncode encrypts each payload with the current key.
func handleEncode(provider KeyProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		var req CodecRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}

		if len(req.Payloads) == 0 {
			writeError(w, http.StatusBadRequest, "payloads array is required and must not be empty")
			return
		}

		keyID := provider.CurrentKeyID()
		key, err := provider.GetKey(keyID)
		if err != nil {
			slog.Error("failed to get encryption key", "error", err)
			writeError(w, http.StatusInternalServerError, "encryption key unavailable")
			return
		}

		resp := CodecResponse{Payloads: make([]Payload, len(req.Payloads))}

		for i, p := range req.Payloads {
			plaintext, err := base64.StdEncoding.DecodeString(p.Data)
			if err != nil {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("payloads[%d]: invalid base64 data", i))
				return
			}

			ciphertext, err := encrypt(key, plaintext)
			if err != nil {
				slog.Error("encryption failed", "index", i, "error", err)
				writeError(w, http.StatusInternalServerError, "encryption failed")
				return
			}

			resp.Payloads[i] = Payload{
				Data: base64.StdEncoding.EncodeToString(ciphertext),
				Metadata: map[string]string{
					metaCodec: codecName,
					metaKeyID: keyID,
				},
			}
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

// handleDecode decrypts each payload using the key ID from its metadata.
func handleDecode(provider KeyProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		var req CodecRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}

		if len(req.Payloads) == 0 {
			writeError(w, http.StatusBadRequest, "payloads array is required and must not be empty")
			return
		}

		resp := CodecResponse{Payloads: make([]Payload, len(req.Payloads))}

		for i, p := range req.Payloads {
			codec := p.Metadata[metaCodec]
			if codec == "" {
				// Not encrypted — pass through unchanged
				resp.Payloads[i] = p
				continue
			}

			if codec != codecName {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("payloads[%d]: unsupported codec %q", i, codec))
				return
			}

			keyID := p.Metadata[metaKeyID]
			if keyID == "" {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("payloads[%d]: missing %s in metadata", i, metaKeyID))
				return
			}

			key, err := provider.GetKey(keyID)
			if err != nil {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("payloads[%d]: unknown key ID %q", i, keyID))
				return
			}

			ciphertext, err := base64.StdEncoding.DecodeString(p.Data)
			if err != nil {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("payloads[%d]: invalid base64 data", i))
				return
			}

			plaintext, err := decrypt(key, ciphertext)
			if err != nil {
				slog.Error("decryption failed", "index", i, "error", err)
				writeError(w, http.StatusBadRequest, fmt.Sprintf("payloads[%d]: decryption failed", i))
				return
			}

			resp.Payloads[i] = Payload{
				Data: base64.StdEncoding.EncodeToString(plaintext),
			}
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

// handleHealth returns a simple health check response.
func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleListKeys returns metadata about registered encryption keys.
func handleListKeys(provider *MultiKeyProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		type keyInfo struct {
			ID      string `json:"id"`
			Current bool   `json:"current"`
		}

		currentID := provider.CurrentKeyID()
		ids := provider.ListKeyIDs()
		keys := make([]keyInfo, len(ids))
		for i, id := range ids {
			keys[i] = keyInfo{ID: id, Current: id == currentID}
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"keys":       keys,
			"total":      len(keys),
			"current_id": currentID,
		})
	}
}

// corsMiddleware adds CORS headers for dashboard integration.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}


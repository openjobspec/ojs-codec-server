package main

import (
	"encoding/json"
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

		payloads, failure := encodePayloadBatch(provider, req.Payloads)
		if failure != nil {
			writeCodecFailure(w, failure)
			return
		}

		writeJSON(w, http.StatusOK, CodecResponse{Payloads: payloads})
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

		payloads, failure := decodePayloadBatch(provider, req.Payloads)
		if failure != nil {
			writeCodecFailure(w, failure)
			return
		}

		writeJSON(w, http.StatusOK, CodecResponse{Payloads: payloads})
	}
}

func writeCodecFailure(w http.ResponseWriter, failure *codecFailure) {
	status := http.StatusBadRequest
	if failure.internal {
		status = http.StatusInternalServerError
	}
	writeError(w, status, failure.message)
}

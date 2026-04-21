package main

import (
	"encoding/base64"
	"fmt"
	"log/slog"
)

const (
	metaCodec = "ojs_codec"
	metaKeyID = "ojs_key_id"
	codecName = "aes-256-gcm"
)

type codecFailure struct {
	message  string
	internal bool
}

func encodePayloadBatch(provider KeyProvider, payloads []Payload) ([]Payload, *codecFailure) {
	if len(payloads) == 0 {
		return nil, &codecFailure{message: "payloads array is required and must not be empty"}
	}

	keyID := provider.CurrentKeyID()
	key, err := provider.GetKey(keyID)
	if err != nil {
		slog.Error("failed to get encryption key", "error", err)
		return nil, &codecFailure{message: "encryption key unavailable", internal: true}
	}

	encoded := make([]Payload, len(payloads))
	for i, payload := range payloads {
		plaintext, err := base64.StdEncoding.DecodeString(payload.Data)
		if err != nil {
			return nil, &codecFailure{message: fmt.Sprintf("payloads[%d]: invalid base64 data", i)}
		}

		ciphertext, err := encrypt(key, plaintext)
		if err != nil {
			slog.Error("encryption failed", "index", i, "error", err)
			return nil, &codecFailure{message: "encryption failed", internal: true}
		}

		encoded[i] = Payload{
			Data: base64.StdEncoding.EncodeToString(ciphertext),
			Metadata: map[string]string{
				metaCodec: codecName,
				metaKeyID: keyID,
			},
		}
	}

	return encoded, nil
}

func decodePayloadBatch(provider KeyProvider, payloads []Payload) ([]Payload, *codecFailure) {
	if len(payloads) == 0 {
		return nil, &codecFailure{message: "payloads array is required and must not be empty"}
	}

	decoded := make([]Payload, len(payloads))
	for i, payload := range payloads {
		codec := payload.Metadata[metaCodec]
		if codec == "" {
			decoded[i] = payload
			continue
		}

		if codec != codecName {
			return nil, &codecFailure{message: fmt.Sprintf("payloads[%d]: unsupported codec %q", i, codec)}
		}

		keyID := payload.Metadata[metaKeyID]
		if keyID == "" {
			return nil, &codecFailure{message: fmt.Sprintf("payloads[%d]: missing %s in metadata", i, metaKeyID)}
		}

		key, err := provider.GetKey(keyID)
		if err != nil {
			return nil, &codecFailure{message: fmt.Sprintf("payloads[%d]: unknown key ID %q", i, keyID)}
		}

		ciphertext, err := base64.StdEncoding.DecodeString(payload.Data)
		if err != nil {
			return nil, &codecFailure{message: fmt.Sprintf("payloads[%d]: invalid base64 data", i)}
		}

		plaintext, err := decrypt(key, ciphertext)
		if err != nil {
			slog.Error("decryption failed", "index", i, "error", err)
			return nil, &codecFailure{message: fmt.Sprintf("payloads[%d]: decryption failed", i)}
		}

		decoded[i] = Payload{
			Data: base64.StdEncoding.EncodeToString(plaintext),
		}
	}

	return decoded, nil
}

package main

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
)

func main() {
	port := envOr("OJS_CODEC_PORT", "8089")
	provider, err := loadKeys()
	if err != nil {
		slog.Error("failed to load encryption keys", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/codec/encode", handleEncode(provider))
	mux.HandleFunc("/codec/decode", handleDecode(provider))
	mux.HandleFunc("/health", handleHealth)

	handler := corsMiddleware(mux)

	addr := ":" + port
	slog.Info("starting OJS Codec Server", "addr", addr, "key_id", provider.CurrentKeyID())
	if err := http.ListenAndServe(addr, handler); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}

// loadKeys reads encryption keys from environment variables.
//
// Supported formats:
//
//	OJS_CODEC_KEY      — hex-encoded 32-byte AES key (key ID defaults to "primary")
//	OJS_CODEC_KEY_ID   — key ID for OJS_CODEC_KEY (default: "primary")
//	OJS_CODEC_KEYS     — comma-separated list of id:hexkey pairs for key rotation
//	                      e.g. "primary:aabbcc...,old-key:ddeeff..."
//
// When both OJS_CODEC_KEY and OJS_CODEC_KEYS are set, all keys are loaded.
func loadKeys() (*MultiKeyProvider, error) {
	singleKey := os.Getenv("OJS_CODEC_KEY")
	multiKeys := os.Getenv("OJS_CODEC_KEYS")
	keyID := envOr("OJS_CODEC_KEY_ID", "primary")

	if singleKey == "" && multiKeys == "" {
		return nil, fmt.Errorf("OJS_CODEC_KEY or OJS_CODEC_KEYS environment variable is required")
	}

	provider := NewMultiKeyProvider(keyID)

	// Load single key
	if singleKey != "" {
		key, err := hex.DecodeString(singleKey)
		if err != nil {
			return nil, fmt.Errorf("OJS_CODEC_KEY: invalid hex: %w", err)
		}
		if err := provider.AddKey(keyID, key); err != nil {
			return nil, fmt.Errorf("OJS_CODEC_KEY: %w", err)
		}
		slog.Info("loaded encryption key", "key_id", keyID)
	}

	// Load multi-key config: "id1:hexkey1,id2:hexkey2"
	if multiKeys != "" {
		pairs := strings.Split(multiKeys, ",")
		for _, pair := range pairs {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			id, hexKey, ok := strings.Cut(pair, ":")
			if !ok {
				return nil, fmt.Errorf("OJS_CODEC_KEYS: invalid format %q (expected id:hexkey)", pair)
			}
			key, err := hex.DecodeString(hexKey)
			if err != nil {
				return nil, fmt.Errorf("OJS_CODEC_KEYS: key %q: invalid hex: %w", id, err)
			}
			if err := provider.AddKey(id, key); err != nil {
				return nil, fmt.Errorf("OJS_CODEC_KEYS: %w", err)
			}
			slog.Info("loaded encryption key", "key_id", id)
		}

		// If no single key was set, use the first multi-key as current
		if singleKey == "" {
			firstPair := strings.TrimSpace(strings.Split(multiKeys, ",")[0])
			firstID, _, _ := strings.Cut(firstPair, ":")
			provider.mu.Lock()
			provider.currentID = firstID
			provider.mu.Unlock()
		}
	}

	return provider, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

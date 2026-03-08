package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
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
	mux.HandleFunc("/codec/keys", handleListKeys(provider))
	mux.HandleFunc("/health", handleHealth)

	handler := corsMiddleware(mux)

	addr := ":" + port
	srv := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		slog.Info("starting OJS Codec Server", "addr", addr, "key_id", provider.CurrentKeyID())
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	<-done
	slog.Info("shutting down codec server")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("shutdown error", "error", err)
	}
	slog.Info("codec server stopped")
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

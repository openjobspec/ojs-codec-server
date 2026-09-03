package main

import "net/http"

func newCodecHTTPHandler(provider *MultiKeyProvider) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/codec/encode", handleEncode(provider))
	mux.HandleFunc("/codec/decode", handleDecode(provider))
	mux.HandleFunc("/codec/keys", handleListKeys(provider))
	mux.HandleFunc("/health", handleHealth)
	return corsMiddleware(mux)
}

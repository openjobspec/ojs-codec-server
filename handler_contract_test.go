package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

func TestHTTPRouteContracts(t *testing.T) {
	provider := testProvider(t)
	handler := existingCodecHTTPHandler(provider)
	plain := base64.StdEncoding.EncodeToString([]byte("plain"))

	tests := []struct {
		name        string
		method      string
		path        string
		origin      string
		body        string
		status      int
		contentType string
		wantBody    string
	}{
		{
			name:        "decode pass through",
			method:      http.MethodPost,
			path:        "/codec/decode",
			origin:      "https://dashboard.example",
			body:        `{"payloads":[{"data":"` + plain + `","metadata":{"trace":"abc"}}]}`,
			status:      http.StatusOK,
			contentType: "application/json",
			wantBody:    `{"payloads":[{"data":"` + plain + `","metadata":{"trace":"abc"}}]}` + "\n",
		},
		{
			name:        "key inventory",
			method:      http.MethodGet,
			path:        "/codec/keys",
			status:      http.StatusOK,
			contentType: "application/json",
			wantBody:    `{"current_id":"test-key","keys":[{"id":"test-key","current":true}],"total":1}` + "\n",
		},
		{
			name:        "health accepts non get",
			method:      http.MethodDelete,
			path:        "/health",
			status:      http.StatusOK,
			contentType: "application/json",
			wantBody:    `{"status":"ok"}` + "\n",
		},
		{
			name:        "encode method rejected",
			method:      http.MethodGet,
			path:        "/codec/encode",
			status:      http.StatusMethodNotAllowed,
			contentType: "application/json",
			wantBody:    `{"error":"method not allowed"}` + "\n",
		},
		{
			name:        "decode method rejected",
			method:      http.MethodGet,
			path:        "/codec/decode",
			status:      http.StatusMethodNotAllowed,
			contentType: "application/json",
			wantBody:    `{"error":"method not allowed"}` + "\n",
		},
		{
			name:        "keys method rejected",
			method:      http.MethodPost,
			path:        "/codec/keys",
			status:      http.StatusMethodNotAllowed,
			contentType: "application/json",
			wantBody:    `{"error":"method not allowed"}` + "\n",
		},
		{
			name:        "unknown route",
			method:      http.MethodGet,
			path:        "/missing",
			status:      http.StatusNotFound,
			contentType: "text/plain; charset=utf-8",
			wantBody:    "404 page not found\n",
		},
		{
			name:     "preflight bypasses routing",
			method:   http.MethodOptions,
			path:     "/missing",
			origin:   "https://dashboard.example",
			status:   http.StatusNoContent,
			wantBody: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, bytes.NewBufferString(tt.body))
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != tt.status {
				t.Fatalf("status = %d, want %d; body = %q", rr.Code, tt.status, rr.Body.String())
			}
			if got := rr.Header().Get("Content-Type"); got != tt.contentType {
				t.Errorf("Content-Type = %q, want %q", got, tt.contentType)
			}
			if got := rr.Body.String(); got != tt.wantBody {
				t.Errorf("body = %q, want %q", got, tt.wantBody)
			}
			if got := rr.Header().Get("Access-Control-Allow-Origin"); got != tt.origin {
				t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, tt.origin)
			}
			if got := rr.Header().Get("Access-Control-Allow-Methods"); got != "POST, GET, OPTIONS" {
				t.Errorf("Access-Control-Allow-Methods = %q", got)
			}
			if got := rr.Header().Get("Access-Control-Allow-Headers"); got != "Content-Type, Authorization" {
				t.Errorf("Access-Control-Allow-Headers = %q", got)
			}
		})
	}
}

func TestEncodeHTTPContract(t *testing.T) {
	provider := testProvider(t)
	body := `{"payloads":[{"data":"` +
		base64.StdEncoding.EncodeToString([]byte("payload")) +
		`","metadata":{"ignored":"value"}}]}`
	req := httptest.NewRequest(http.MethodPost, "/codec/encode", bytes.NewBufferString(body))
	rr := httptest.NewRecorder()

	handleEncode(provider).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %q", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
	pattern := regexp.MustCompile(`^\{"payloads":\[\{"data":"[A-Za-z0-9+/]+={0,2}","metadata":\{"ojs_codec":"aes-256-gcm","ojs_key_id":"test-key"\}\}\]\}\n$`)
	if !pattern.MatchString(rr.Body.String()) {
		t.Fatalf("unexpected encoded body shape/order: %q", rr.Body.String())
	}
}

func TestCodecHTTPErrorContracts(t *testing.T) {
	goodKey := []byte("01234567890123456789012345678901")
	tests := []struct {
		name     string
		handler  http.Handler
		body     string
		status   int
		wantBody string
	}{
		{
			name:     "encode invalid json",
			handler:  handleEncode(&contractKeyProvider{}),
			body:     `{`,
			status:   http.StatusBadRequest,
			wantBody: `{"error":"invalid JSON: unexpected EOF"}` + "\n",
		},
		{
			name:     "encode empty payloads",
			handler:  handleEncode(&contractKeyProvider{}),
			body:     `{"payloads":[]}`,
			status:   http.StatusBadRequest,
			wantBody: `{"error":"payloads array is required and must not be empty"}` + "\n",
		},
		{
			name: "encode unavailable key",
			handler: handleEncode(&contractKeyProvider{
				current: "missing",
				err:     errors.New("not found"),
			}),
			body:     `{"payloads":[{"data":"cGF5bG9hZA=="}]}`,
			status:   http.StatusInternalServerError,
			wantBody: `{"error":"encryption key unavailable"}` + "\n",
		},
		{
			name: "encode invalid base64 at ordered index",
			handler: handleEncode(&contractKeyProvider{
				current: "key",
				key:     goodKey,
			}),
			body:     `{"payloads":[{"data":"cGF5bG9hZA=="},{"data":"!"}]}`,
			status:   http.StatusBadRequest,
			wantBody: `{"error":"payloads[1]: invalid base64 data"}` + "\n",
		},
		{
			name: "encode cipher failure",
			handler: handleEncode(&contractKeyProvider{
				current: "key",
				key:     []byte("short"),
			}),
			body:     `{"payloads":[{"data":"cGF5bG9hZA=="}]}`,
			status:   http.StatusInternalServerError,
			wantBody: `{"error":"encryption failed"}` + "\n",
		},
		{
			name:     "decode invalid json",
			handler:  handleDecode(&contractKeyProvider{}),
			body:     `{`,
			status:   http.StatusBadRequest,
			wantBody: `{"error":"invalid JSON: unexpected EOF"}` + "\n",
		},
		{
			name:     "decode empty payloads",
			handler:  handleDecode(&contractKeyProvider{}),
			body:     `{"payloads":null}`,
			status:   http.StatusBadRequest,
			wantBody: `{"error":"payloads array is required and must not be empty"}` + "\n",
		},
		{
			name:     "decode unsupported codec precedes key checks",
			handler:  handleDecode(&contractKeyProvider{}),
			body:     `{"payloads":[{"data":"!","metadata":{"ojs_codec":"other"}}]}`,
			status:   http.StatusBadRequest,
			wantBody: `{"error":"payloads[0]: unsupported codec \"other\""}` + "\n",
		},
		{
			name:     "decode missing key precedes base64",
			handler:  handleDecode(&contractKeyProvider{}),
			body:     `{"payloads":[{"data":"!","metadata":{"ojs_codec":"aes-256-gcm"}}]}`,
			status:   http.StatusBadRequest,
			wantBody: `{"error":"payloads[0]: missing ojs_key_id in metadata"}` + "\n",
		},
		{
			name: "decode unknown key precedes base64",
			handler: handleDecode(&contractKeyProvider{
				err: errors.New("not found"),
			}),
			body:     `{"payloads":[{"data":"!","metadata":{"ojs_codec":"aes-256-gcm","ojs_key_id":"missing"}}]}`,
			status:   http.StatusBadRequest,
			wantBody: `{"error":"payloads[0]: unknown key ID \"missing\""}` + "\n",
		},
		{
			name: "decode invalid base64",
			handler: handleDecode(&contractKeyProvider{
				key: goodKey,
			}),
			body:     `{"payloads":[{"data":"!","metadata":{"ojs_codec":"aes-256-gcm","ojs_key_id":"key"}}]}`,
			status:   http.StatusBadRequest,
			wantBody: `{"error":"payloads[0]: invalid base64 data"}` + "\n",
		},
		{
			name: "decode cipher failure",
			handler: handleDecode(&contractKeyProvider{
				key: goodKey,
			}),
			body:     `{"payloads":[{"data":"c2hvcnQ=","metadata":{"ojs_codec":"aes-256-gcm","ojs_key_id":"key"}}]}`,
			status:   http.StatusBadRequest,
			wantBody: `{"error":"payloads[0]: decryption failed"}` + "\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(tt.body))
			rr := httptest.NewRecorder()

			tt.handler.ServeHTTP(rr, req)

			if rr.Code != tt.status {
				t.Fatalf("status = %d, want %d; body = %q", rr.Code, tt.status, rr.Body.String())
			}
			if got := rr.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type = %q", got)
			}
			if got := rr.Body.String(); got != tt.wantBody {
				t.Errorf("body = %q, want %q", got, tt.wantBody)
			}
		})
	}
}

func TestJSONRenderingFieldOrder(t *testing.T) {
	rr := httptest.NewRecorder()

	writeJSON(rr, http.StatusCreated, map[string]any{
		"z": 1,
		"a": map[string]string{"z": "last", "a": "first"},
	})

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rr.Code)
	}
	if got := rr.Body.String(); got != `{"a":{"a":"first","z":"last"},"z":1}`+"\n" {
		t.Fatalf("body = %q", got)
	}
}

func existingCodecHTTPHandler(provider *MultiKeyProvider) http.Handler {
	return newCodecHTTPHandler(provider)
}

type contractKeyProvider struct {
	current string
	key     []byte
	err     error
}

func (p *contractKeyProvider) GetKey(string) ([]byte, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.key, nil
}

func (p *contractKeyProvider) CurrentKeyID() string {
	return p.current
}

func TestPayloadWireTags(t *testing.T) {
	raw, err := json.Marshal(CodecResponse{Payloads: []Payload{{Data: "x"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(raw); got != `{"payloads":[{"data":"x"}]}` {
		t.Fatalf("wire shape = %s", got)
	}
}

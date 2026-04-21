package main

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"testing"
)

var (
	_ func(string) *MultiKeyProvider                                                  = NewMultiKeyProvider
	_ func(*MultiKeyProvider, string, []byte) error                                   = (*MultiKeyProvider).AddKey
	_ func(*MultiKeyProvider, string) ([]byte, error)                                 = (*MultiKeyProvider).GetKey
	_ func(*MultiKeyProvider) string                                                  = (*MultiKeyProvider).CurrentKeyID
	_ func(*MultiKeyProvider) []string                                                = (*MultiKeyProvider).ListKeyIDs
	_ func(Signer, Attestor, *KeyRotator) *AttestPipeline                             = NewAttestPipeline
	_ func(*AttestPipeline, context.Context, []byte, string) (*AttestEnvelope, error) = (*AttestPipeline).Run
	_ func(*AttestPipeline, context.Context, *AttestEnvelope) error                   = (*AttestPipeline).Verify
	_ func(string, ed25519.PrivateKey) *KeyRotator                                    = NewKeyRotator
	_ func(*KeyRotator) (string, any)                                                 = (*KeyRotator).Current
	_ func(*KeyRotator, any, string)                                                  = (*KeyRotator).Rotate
	_ func(*KeyRotator, string, []byte, []byte) error                                 = (*KeyRotator).Verify
	_ func(*KeyRotator) map[string]ed25519.PublicKey                                  = (*KeyRotator).PublicKeys
	_ func(*KeyRotator) *JWKSHandler                                                  = NewJWKSHandler
	_ func(string) (*KeyRotator, error)                                               = GenerateKeyRotator
	_ http.Handler                                                                    = (*JWKSHandler)(nil)
	_ func() *Registry                                                                = NewRegistry
	_ func(*Registry, *Plugin) error                                                  = (*Registry).Register
	_ func(*Registry, string) (*Plugin, bool)                                         = (*Registry).Get
	_ func(*Registry, string) Signer                                                  = (*Registry).Signer
	_ func(*Registry, string) Attestor                                                = (*Registry).Attestor
	_ func(*Registry) []string                                                        = (*Registry).Names
	_ func(string) Signer                                                             = NewStubSigner
	_ func(string) Attestor                                                           = NewStubAttestor
	_ func(Ed25519KeyProvider) *Ed25519Signer                                         = NewEd25519Signer
	_ func(*Ed25519Signer) string                                                     = (*Ed25519Signer).Algorithm
	_ func(*Ed25519Signer, context.Context, string, []byte) ([]byte, error)           = (*Ed25519Signer).Sign
	_ func(*Ed25519Signer, context.Context, string, []byte, []byte) error             = (*Ed25519Signer).Verify
	_ func() *MemoryKeyProvider                                                       = NewMemoryKeyProvider
	_ func(*MemoryKeyProvider, string) (string, error)                                = (*MemoryKeyProvider).Generate
	_ func(*MemoryKeyProvider, string, ed25519.PrivateKey) error                      = (*MemoryKeyProvider).Import
	_ func(*MemoryKeyProvider, string) (ed25519.PrivateKey, error)                    = (*MemoryKeyProvider).PrivateKey
	_ func(*MemoryKeyProvider, string) (ed25519.PublicKey, error)                     = (*MemoryKeyProvider).PublicKey
)

var (
	_ KeyProvider        = (*MultiKeyProvider)(nil)
	_ Signer             = (*stubSigner)(nil)
	_ Signer             = (*Ed25519Signer)(nil)
	_ Attestor           = (*stubAttestor)(nil)
	_ Ed25519KeyProvider = (*MemoryKeyProvider)(nil)
)

var (
	_ = Payload{Data: "", Metadata: map[string]string{}}
	_ = CodecRequest{Payloads: []Payload{}}
	_ = CodecResponse{Payloads: []Payload{}}
	_ = AttestEnvelope{
		Payload:      []byte{},
		Signature:    []byte{},
		KeyID:        "",
		Quote:        []byte{},
		Jurisdiction: "",
		IssuedAt:     "",
	}
	_ = Plugin{Name: "", Signer: nil, Attestor: nil}
)

func TestExportedConstantValues(t *testing.T) {
	values := map[string]string{
		"SigAlgEd25519":   SigAlgEd25519,
		"SigAlgMLDSA65":   SigAlgMLDSA65,
		"SigAlgRSAPSS":    SigAlgRSAPSS,
		"AttestAWSNitro":  AttestAWSNitro,
		"AttestIntelTDX":  AttestIntelTDX,
		"AttestAMDSEVSNP": AttestAMDSEVSNP,
		"AttestPQCOnly":   AttestPQCOnly,
	}
	want := map[string]string{
		"SigAlgEd25519":   "ed25519",
		"SigAlgMLDSA65":   "ml-dsa-65",
		"SigAlgRSAPSS":    "rsa-pss-sha256",
		"AttestAWSNitro":  "aws-nitro",
		"AttestIntelTDX":  "intel-tdx",
		"AttestAMDSEVSNP": "amd-sev-snp",
		"AttestPQCOnly":   "pqc-only",
	}
	for name, expected := range want {
		if values[name] != expected {
			t.Errorf("%s = %q, want %q", name, values[name], expected)
		}
	}
}

func TestStubByteAndErrorContracts(t *testing.T) {
	ctx := context.Background()
	signer := NewStubSigner(SigAlgMLDSA65)
	signature, err := signer.Sign(ctx, "key-1", []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(signature); got != "stub-sig:ml-dsa-65:key-1:5" {
		t.Fatalf("signature = %q", got)
	}
	if err := signer.Verify(ctx, "key-1", []byte("hello"), signature); err != nil {
		t.Fatal(err)
	}
	if got := errorString(signer.Verify(ctx, "key-1", []byte("other!"), signature)); got != "stub signature mismatch" {
		t.Fatalf("signer error = %q", got)
	}

	attestor := NewStubAttestor(AttestAWSNitro)
	document, err := attestor.Attest(ctx, []byte("digest"))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(document); got != "stub-attest:aws-nitro:6" {
		t.Fatalf("document = %q", got)
	}
	if err := attestor.Verify(ctx, []byte("digest"), document); err != nil {
		t.Fatal(err)
	}
	if got := errorString(attestor.Verify(ctx, []byte("other!!"), document)); got != "stub attestation mismatch" {
		t.Fatalf("attestor error = %q", got)
	}
}

func TestRegistryExactValidationContracts(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*Registry)
		plugin  *Plugin
		want    string
	}{
		{
			name:   "nil",
			plugin: nil,
			want:   "plugin must be non-nil and named",
		},
		{
			name:   "unnamed",
			plugin: &Plugin{Signer: NewStubSigner(SigAlgEd25519)},
			want:   "plugin must be non-nil and named",
		},
		{
			name:   "empty",
			plugin: &Plugin{Name: "empty"},
			want:   `plugin "empty" must supply at least one of Signer or Attestor`,
		},
		{
			name:   "unknown signer",
			plugin: &Plugin{Name: "unknown", Signer: NewStubSigner("unknown")},
			want:   `plugin "unknown" claims unknown signature algorithm "unknown" (allowed: [ed25519 ml-dsa-65 rsa-pss-sha256])`,
		},
		{
			name:   "unknown attestor",
			plugin: &Plugin{Name: "unknown", Attestor: NewStubAttestor("unknown")},
			want:   `plugin "unknown" claims unknown attestation type "unknown" (allowed: [amd-sev-snp aws-nitro intel-tdx pqc-only])`,
		},
		{
			name: "duplicate name",
			prepare: func(r *Registry) {
				_ = r.Register(&Plugin{Name: "duplicate", Signer: NewStubSigner(SigAlgEd25519)})
			},
			plugin: &Plugin{Name: "duplicate", Attestor: NewStubAttestor(AttestAWSNitro)},
			want:   `plugin "duplicate" already registered`,
		},
		{
			name: "signer collision",
			prepare: func(r *Registry) {
				_ = r.Register(&Plugin{Name: "first", Signer: NewStubSigner(SigAlgEd25519)})
			},
			plugin: &Plugin{Name: "second", Signer: NewStubSigner(SigAlgEd25519)},
			want:   `signature algorithm "ed25519" already covered by plugin "first"`,
		},
		{
			name: "attestor collision",
			prepare: func(r *Registry) {
				_ = r.Register(&Plugin{Name: "first", Attestor: NewStubAttestor(AttestAWSNitro)})
			},
			plugin: &Plugin{Name: "second", Attestor: NewStubAttestor(AttestAWSNitro)},
			want:   `attestation type "aws-nitro" already covered by plugin "first"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := NewRegistry()
			if tt.prepare != nil {
				tt.prepare(registry)
			}
			if got := errorString(registry.Register(tt.plugin)); got != tt.want {
				t.Fatalf("error = %q, want %q", got, tt.want)
			}
		})
	}
}

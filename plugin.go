package main

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// Algorithm identifiers (IANA-style strings used in M1 verifiable-compute envelope `ext_attest`).
const (
	SigAlgEd25519  = "ed25519"
	SigAlgMLDSA65  = "ml-dsa-65"  // FIPS 204 / Dilithium-3 (PQC)
	SigAlgRSAPSS   = "rsa-pss-sha256"

	AttestAWSNitro = "aws-nitro"
	AttestIntelTDX = "intel-tdx"
	AttestAMDSEVSNP = "amd-sev-snp"
	AttestPQCOnly  = "pqc-only" // no hardware enclave; signature-only attestation
)

// Signer produces and verifies detached signatures over arbitrary bytes.
//
// Implementations MUST be safe for concurrent use. The `keyID` argument
// identifies the signing key (mirrors KeyProvider semantics for rotation).
type Signer interface {
	Algorithm() string
	Sign(ctx context.Context, keyID string, message []byte) (signature []byte, err error)
	Verify(ctx context.Context, keyID string, message, signature []byte) error
}

// Attestor produces a hardware- or software-backed attestation document
// that binds a payload (typically a SHA-256 digest of job inputs/outputs)
// to a measurement of the executing environment.
//
// See M1 Verifiable Compute spec: ext_attest envelope key.
type Attestor interface {
	Type() string
	Attest(ctx context.Context, payload []byte) (document []byte, err error)
	Verify(ctx context.Context, payload, document []byte) error
}

// Plugin is the umbrella registration unit for a non-encryption codec capability.
// A single plugin MAY supply any subset of {Signer, Attestor}.
type Plugin struct {
	Name     string
	Signer   Signer
	Attestor Attestor
}

// Registry holds plugins by name. It is the single integration seam that
// SDKs and the codec server discover at startup.
type Registry struct {
	mu      sync.RWMutex
	plugins map[string]*Plugin
}

// NewRegistry returns an empty plugin registry.
func NewRegistry() *Registry {
	return &Registry{plugins: make(map[string]*Plugin)}
}

// knownSigAlgs is the closed set of acceptable Signer.Algorithm() return values.
// New algorithms MUST be added here AND to the registry doc before plugins
// claiming them are accepted. See SECURITY-REVIEW-signer.md F-3.
var knownSigAlgs = map[string]struct{}{
	SigAlgEd25519: {},
	SigAlgMLDSA65: {},
	SigAlgRSAPSS:  {},
}

// knownAttestTypes mirrors knownSigAlgs for Attestor.Type().
var knownAttestTypes = map[string]struct{}{
	AttestAWSNitro:  {},
	AttestIntelTDX:  {},
	AttestAMDSEVSNP: {},
	AttestPQCOnly:   {},
}

// Register adds a plugin. Returns an error if the name is already taken
// (fail-fast: silent shadowing of crypto plugins is a foot-gun) or if the
// plugin claims an algorithm or attestation type that isn't in the closed
// known set, or if another plugin already covers that algorithm/type
// (silent shadowing via map-iteration ordering would otherwise be possible).
// See SECURITY-REVIEW-signer.md findings F-3 and F-4.
func (r *Registry) Register(p *Plugin) error {
	if p == nil || p.Name == "" {
		return fmt.Errorf("plugin must be non-nil and named")
	}
	if p.Signer == nil && p.Attestor == nil {
		return fmt.Errorf("plugin %q must supply at least one of Signer or Attestor", p.Name)
	}
	if p.Signer != nil {
		if _, ok := knownSigAlgs[p.Signer.Algorithm()]; !ok {
			return fmt.Errorf("plugin %q claims unknown signature algorithm %q (allowed: %v)",
				p.Name, p.Signer.Algorithm(), sortedKeys(knownSigAlgs))
		}
	}
	if p.Attestor != nil {
		if _, ok := knownAttestTypes[p.Attestor.Type()]; !ok {
			return fmt.Errorf("plugin %q claims unknown attestation type %q (allowed: %v)",
				p.Name, p.Attestor.Type(), sortedKeys(knownAttestTypes))
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.plugins[p.Name]; exists {
		return fmt.Errorf("plugin %q already registered", p.Name)
	}
	for _, existing := range r.plugins {
		if p.Signer != nil && existing.Signer != nil && existing.Signer.Algorithm() == p.Signer.Algorithm() {
			return fmt.Errorf("signature algorithm %q already covered by plugin %q", p.Signer.Algorithm(), existing.Name)
		}
		if p.Attestor != nil && existing.Attestor != nil && existing.Attestor.Type() == p.Attestor.Type() {
			return fmt.Errorf("attestation type %q already covered by plugin %q", p.Attestor.Type(), existing.Name)
		}
	}
	r.plugins[p.Name] = p
	return nil
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Get returns the plugin registered under name, or (nil, false).
func (r *Registry) Get(name string) (*Plugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.plugins[name]
	return p, ok
}

// Signer returns the first registered signer matching algorithm, or nil.
func (r *Registry) Signer(algorithm string) Signer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, p := range r.plugins {
		if p.Signer != nil && p.Signer.Algorithm() == algorithm {
			return p.Signer
		}
	}
	return nil
}

// Attestor returns the first registered attestor matching type, or nil.
func (r *Registry) Attestor(attestType string) Attestor {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, p := range r.plugins {
		if p.Attestor != nil && p.Attestor.Type() == attestType {
			return p.Attestor
		}
	}
	return nil
}

// Names returns sorted plugin names for diagnostics.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.plugins))
	for name := range r.plugins {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// ----- Stub implementations for early integration testing -----
// These are intentionally minimal and NOT cryptographically secure on their own;
// real Ed25519/ML-DSA/Nitro implementations land in M1 P1 Prototype.

// stubSigner deterministically returns "sig:<alg>:<keyID>:<len>" — useful only
// for wiring/contract tests. Replace before any non-test use.
type stubSigner struct{ alg string }

// NewStubSigner returns a placeholder signer for the given algorithm.
// It is exported so tests in dependent SDKs can exercise the contract end-to-end
// before real crypto is wired in. Logs a startup warning when used.
func NewStubSigner(algorithm string) Signer { return &stubSigner{alg: algorithm} }

func (s *stubSigner) Algorithm() string { return s.alg }

func (s *stubSigner) Sign(_ context.Context, keyID string, message []byte) ([]byte, error) {
	return []byte(fmt.Sprintf("stub-sig:%s:%s:%d", s.alg, keyID, len(message))), nil
}

func (s *stubSigner) Verify(_ context.Context, keyID string, message, signature []byte) error {
	want := fmt.Sprintf("stub-sig:%s:%s:%d", s.alg, keyID, len(message))
	if string(signature) != want {
		return fmt.Errorf("stub signature mismatch")
	}
	return nil
}

// stubAttestor returns a placeholder attestation envelope.
type stubAttestor struct{ kind string }

// NewStubAttestor returns a placeholder attestor for the given environment type.
func NewStubAttestor(kind string) Attestor { return &stubAttestor{kind: kind} }

func (a *stubAttestor) Type() string { return a.kind }

func (a *stubAttestor) Attest(_ context.Context, payload []byte) ([]byte, error) {
	return []byte(fmt.Sprintf("stub-attest:%s:%d", a.kind, len(payload))), nil
}

func (a *stubAttestor) Verify(_ context.Context, payload, document []byte) error {
	want := fmt.Sprintf("stub-attest:%s:%d", a.kind, len(payload))
	if string(document) != want {
		return fmt.Errorf("stub attestation mismatch")
	}
	return nil
}

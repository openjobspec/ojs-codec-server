# Codec-Server Signer/Attestor Contract — Security Review (W0 F3 follow-up)

**Status:** Internal review draft. Sign off required before any
non-stub `Signer`/`Attestor` implementation merges.

**Scope:** The contracts in `plugin.go` (added in W0 F3) — `Signer`,
`Attestor`, `Plugin`, `Registry`, plus the AES-256-GCM `KeyProvider`
path that lives alongside them. Excludes: the production crypto
implementations themselves (they don't exist yet — that's M1 P1).

## Threat model

### Trust boundaries

```
+----------------+       +-------------------+       +-----------------+
| Job producer   | --enq-> ojs-backend       | --deq->  Worker         |
| (untrusted) |       | (semi-trusted)    |       | (trusted)       |
+----------------+       +-------------------+       +--------+--------+
                                                              |
                                                       loads plugins
                                                              |
                                                              v
                                                     +------------------+
                                                     | codec-server     |
                                                     | (high trust)     |
                                                     +------------------+
```

### Assets

| Asset | Confidentiality | Integrity | Availability |
|---|---|---|---|
| AES key material | **Critical** | Critical | High |
| Signing private key | **Critical** | Critical | High |
| Attestation root cert | Public | Critical | High |
| Plugin registry contents | Low | **Critical** (silent shadowing = bypass) | Medium |
| Encrypted job payloads | Critical | Critical | Medium |

### Adversaries

1. **Network attacker** — sees ciphertexts; cannot reach codec-server.
2. **Compromised producer** — can craft malicious `ext_attest` envelope.
3. **Compromised backend** — can mutate envelopes in flight; can attempt
   to swap `key_id`.
4. **Local attacker on worker host** — can attempt plugin shadowing;
   process memory inspection.
5. **Malicious plugin** — a third-party `Signer`/`Attestor` shipped as
   a Go module that misbehaves once loaded.

## Findings against the W0 F3 contract

### F-1 (HIGH) — Plugin loading is currently in-process

**Issue.** `Registry.Register` puts plugins in the same address space.
A malicious plugin can read other plugins' keys via reflection or
unsafe pointers.

**Mitigation (P1):** Document that codec-server only loads plugins
shipped in the same binary in P1. Out-of-process plugins (gRPC) are a
P2+ feature; do NOT enable until reviewed.

**Test (recommended):** Add a build-tag-gated test asserting that the
plugin set is the expected static list at startup.

### F-2 (HIGH) — Stub signers verify by **structural string match**

**Issue.** `stubSigner.Verify` does `string(signature) != want`. This
is *intentionally* not constant-time, because stubs MUST NEVER ship to
production — but a copy-paste into a real impl would create a timing
oracle.

**Mitigation:** Add a `// SECURITY: stub only — do not use as a template`
comment to both stub structs. Real impls MUST use
`crypto/subtle.ConstantTimeCompare` on the failure path and pass through
`crypto/ed25519` etc. for the success path (which is already
constant-time).

### F-3 (MEDIUM) — `Algorithm()`/`Type()` strings are unvalidated

**Issue.** The registry trusts `Signer.Algorithm()` to return a
well-known string. A buggy or malicious plugin could return
`"ed25519"` while internally using a weaker scheme; lookup by algorithm
would silently route signing requests to the weak impl.

**Mitigation:** `Registry.Register` should validate `Signer.Algorithm()`
against the registry constants in `plugin.go` (`SigAlgEd25519`, etc.)
and reject unknown values unless an explicit `WithExperimental()` option
is passed.

**Test (recommended):** Property test that registering a plugin
returning an unknown algorithm string fails.

### F-4 (MEDIUM) — Duplicate name rejection is fail-loud, but algorithm collision is fail-silent

**Issue.** `Registry.Register` rejects duplicate **names** but happily
accepts two plugins claiming the same algorithm. `Registry.Signer(alg)`
returns the first one it finds via map iteration (non-deterministic).

**Mitigation:** Either (a) reject algorithm collisions outright, or
(b) require callers to use `Get(name)` for production paths and treat
`Signer(alg)` as a debug-only helper. Recommend (a).

**Test (recommended):** Add a test asserting that registering two
plugins with the same algorithm fails.

### F-5 (LOW) — `Sign`/`Attest` accept context but no timeout enforcement

**Issue.** Stubs ignore `ctx`; real impls might too if not careful.
A hanging HSM call could DoS the codec-server.

**Mitigation:** Document a hard 30s deadline on Sign/Attest calls in
the codec-server HTTP handler (`handler.go`) — already partially in
place via standard timeouts; verify and document.

### F-6 (LOW) — `key_id` is opaque

**Issue.** `Sign(ctx, keyID, ...)` accepts arbitrary strings. No length
limit, no character-set restriction. A malicious producer could supply
a key_id like `../../../../etc/secrets`.

**Mitigation:** Add a `validateKeyID(string) error` helper; require it
in any plugin implementation that maps key_id to filesystem paths.
P1-blocker for any file-backed key store.

### F-7 (LOW) — No replay defense in the contract itself

**Issue.** A signature over a payload can be re-presented with a
different envelope unless the envelope binds payload + nonce + time.

**Mitigation:** This is correctly punted to `ext_attest` (see RFC-0010
open question 2). The `Signer` interface itself doesn't need to know.
But document this **explicitly** in the `Signer` godoc so impls don't
assume the framework handles freshness.

## Property-based test scaffolding (recommendations)

`go test ./... -fuzz` is the right tool. Add these tests to
`plugin_property_test.go`:

```go
package main

import (
    "context"
    "testing"
)

// FuzzSignerVerifyRoundTrip: any (keyID, message) signed by stub MUST verify.
func FuzzSignerVerifyRoundTrip(f *testing.F) {
    f.Add("k1", []byte("hello"))
    s := NewStubSigner(SigAlgEd25519)
    f.Fuzz(func(t *testing.T, keyID string, msg []byte) {
        ctx := context.Background()
        sig, err := s.Sign(ctx, keyID, msg)
        if err != nil { return }
        if err := s.Verify(ctx, keyID, msg, sig); err != nil {
            t.Errorf("round-trip failed for keyID=%q msg=%q: %v", keyID, msg, err)
        }
    })
}

// FuzzSignerTamperDetect: tampering MUST cause verification failure.
func FuzzSignerTamperDetect(f *testing.F) {
    f.Add("k1", []byte("hello"), []byte("HELLO"))
    s := NewStubSigner(SigAlgEd25519)
    f.Fuzz(func(t *testing.T, keyID string, msg, tamper []byte) {
        if string(msg) == string(tamper) { return }
        ctx := context.Background()
        sig, err := s.Sign(ctx, keyID, msg)
        if err != nil { return }
        if err := s.Verify(ctx, keyID, tamper, sig); err == nil {
            t.Errorf("tamper not detected: keyID=%q msg=%q tamper=%q", keyID, msg, tamper)
        }
    })
}
```

These run via `go test -fuzz=Fuzz -fuzztime=30s ./...` and will be
enabled in CI once a real cryptographic `Signer` is in place.

The first concrete test (`plugin_pentest_test.go`) is being added in
this commit and exercises findings F-3 and F-4 against the current
contract — both currently fail (which is correct — they document
fix-before-merge requirements for the next iteration).

## Sign-off

- [ ] Crypto lead
- [ ] codec-server maintainer
- [ ] Independent TAG-Security reviewer (target: Q+2 per CNCF
      engagement plan)

## References

- NIST SP 800-90A (random number generation) — informs nonce handling.
- FIPS 204 (ML-DSA) — <https://csrc.nist.gov/pubs/fips/204/final>
- Go `crypto/subtle` — <https://pkg.go.dev/crypto/subtle>
- Sigstore plugin model — <https://docs.sigstore.dev/cosign/signing/overview/>

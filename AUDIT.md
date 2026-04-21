# Actor-Based SRP and Clean-Code Audit

## Summary

- `OJS-CODEC-001` remains intact: `ojs-attest` process dispatch, command/file orchestration, and byte-sensitive evidence policy stay separated without changing CLI flags, output, errors, or signed bytes.
- `OJS-CODEC-002`, `OJS-CODEC-003`, and `OJS-CODEC-004` are implemented as same-package file splits around existing state owners and private actors; exported declarations, plugin ABI, routes, statuses, JSON, crypto, attestation, and JWKS bytes are unchanged.
- Characterization tests now freeze pipeline digest/signature/quote flow, KeyRotator custody, exact single-key JWKS output, every registered HTTP route, CORS headers, status/body/error precedence, JSON field order, plugin stub bytes, and exported method signatures.
- The leading-empty `OJS_CODEC_KEYS` defect is fixed by selecting the first successfully loaded non-empty entry when no single key is configured; duplicate overwrite behavior, empty IDs, all-empty input, pair order, and exact errors remain characterized.
- Deterministic multi-key/JWKS ordering and ignored JSON encoder errors were assessed but not changed: repository contracts define membership and successful response bytes, not map-derived ordering or failed-writer behavior.

## Findings and Final Outcomes

| ID | original location | actors-in-conflict | outcome |
|---|---|---|---|
| OJS-CODEC-001 | pre-refactor `cmd/ojs-attest/main.go` | CLI UX and flags; filesystem I/O; evidence serialization; signing and verification policy | Complete in the preserved first pass: `main.go`, `commands.go`, and `evidence.go` retain the frozen CLI and signing contracts. |
| OJS-CODEC-002 | pre-refactor `attest.go` | attestation workflow; signing-key custody/rotation; JWKS HTTP publication | Complete: pipeline workflow remains in `attest.go`, custody and generation moved to `key_rotator.go`, and publication moved to `jwks_handler.go`. |
| OJS-CODEC-003 | pre-refactor `handler.go` | batch codec policy; HTTP adaptation; route composition; key inventory; health; CORS; JSON rendering | Complete: responsibilities now reside in `codec_batch.go`, `codec_http.go`, `http_routes.go`, `key_inventory_handler.go`, `health_handler.go`, `cors.go`, and `json_response.go`. |
| OJS-CODEC-004 | pre-refactor `plugin.go` | Registry ABI/collision policy; insecure exported integration stubs | Complete: Registry policy remains in `plugin.go`; byte-identical stubs moved to `plugin_stubs.go`. |
| leading-empty key selection | pre-refactor `main.go` multi-key parsing | environment parsing; active-key selection | Complete: current ID is taken from the first successfully loaded pair rather than the first raw comma-separated entry. |

## Production Module Assessment

| module | actor and state partition | assessment |
|---|---|---|
| `main.go` | Process lifecycle and environment-backed AES key loading. | Acceptable; the current-ID bug is fixed without changing environment names or parsing errors. |
| `codec.go` | Synchronized AES key custody plus AES-GCM primitives. | Cohesive; `ListKeyIDs` intentionally retains its unspecified map-derived order. |
| `codec_batch.go` | Encode/decode batch validation, ordering, key lookup, crypto invocation, metadata projection, and logging. | Cohesive policy unit with no HTTP parsing or rendering. |
| `codec_http.go` | Codec request decoding, method enforcement, failure-to-status adaptation, and response wrapping. | Cohesive HTTP adapter; exported wire types and tags are unchanged. |
| `http_routes.go` | Exact route registration and CORS composition. | Cohesive composition root used by `main`. |
| `key_inventory_handler.go` | Encryption-key inventory projection. | Cohesive; output shape and map-derived key order are preserved. |
| `health_handler.go` | Health response behavior. | Cohesive; all methods still receive the same 200 JSON response. |
| `cors.go` | Dashboard CORS headers and OPTIONS short-circuit. | Cohesive; exact header values and 204 empty body are characterized. |
| `json_response.go` | JSON success/error framing. | Cohesive; newline, content type, status timing, and field ordering remain unchanged. |
| `attest.go` | Attestation pipeline workflow and envelope wire type. | Cohesive workflow owner. |
| `key_rotator.go` | Ed25519 private-key custody, rotation, verification, public-key projection, and generation. | Cohesive synchronized state owner. |
| `jwks_handler.go` | JWKS request method policy and JSON publication. | Cohesive HTTP publication owner; exact fields and single-key body are characterized. |
| `plugin.go` | Public plugin ABI, known-value policy, collision rejection, lookup, and diagnostics. | Cohesive registry policy owner. |
| `plugin_stubs.go` | Exported insecure signer/attestor integration fixtures. | Cohesive compatibility fixture; exact bytes and errors are characterized. |
| `ed25519_signer.go` | Ed25519 signer policy and injectable in-memory key storage. | Acceptable; existing provider injection keeps the partitions testable. |
| `cmd/ojs-attest/main.go` | Process dispatch, usage, exit codes, and top-level output. | Cohesive CLI entry actor. |
| `cmd/ojs-attest/commands.go` | Flags, path validation, file/stdin I/O, and command output. | Cohesive command adapter with frozen validation and I/O ordering. |
| `cmd/ojs-attest/evidence.go` | Evidence construction, validation, freshness, canonical digest, signing payload, and verification. | Cohesive byte-sensitive evidence policy. |
| `cmd/ojs-attest/tee.go` | TEE structural validation and vendor dispatch. | Cohesive validation actor. |

## Clean-Code and Guardrail Assessment

| dimension | final assessment |
|---|---|
| Actor separation | Each remaining wide module was split by an existing state owner or independently changing private policy; no pass-through interface or speculative abstraction was introduced. |
| Public API and plugin ABI | `api_contract_test.go` uses compile-time function/method assignments, interface assertions, exported struct literals, and exact constant checks to guard exported declarations. |
| HTTP contract | `handler_contract_test.go` freezes registered routes, unknown-route behavior, methods, headers, statuses, bodies, CORS, JSON newlines/field order, and validation/error precedence. |
| Crypto and attestation bytes | Existing AES tests remain unchanged; new tests freeze SHA-256 pipeline inputs, signature/quote propagation, envelope JSON, KeyRotator behavior, JWKS fields/body, and stub bytes. |
| Errors and ordering | Exact HTTP, Registry, pipeline, key-configuration, and stub errors are characterized. Validation and payload traversal order remain unchanged. |
| Side effects | Environment reads, logs, randomness, clocks, locks, filesystem behavior, status timing, and encoder calls remain at their existing boundaries. |
| Dependencies and layering | No dependency or package boundary was added; the package remains flat and acyclic. |

## Completed Refactor Sequence

1. Preserved the first-pass `ojs-attest` split and its signing-payload/canonical-digest tests.
2. Added byte, API, HTTP, route, header, status, body, field-order, error-precedence, Registry, and stub characterization before production changes.
3. Split `AttestPipeline`, `KeyRotator`, and `JWKSHandler` responsibilities by file.
4. Split codec batch policy, HTTP adaptation, routes, key inventory, health, CORS, and JSON rendering.
5. Split Registry policy from exported integration stubs.
6. Added failing leading-empty environment regression coverage, then fixed current-ID selection with the minimal parser-state change.
7. Assessed deterministic ordering and ignored encoder errors against repository contracts.

## Deferred After Assessment

| item | final decision |
|---|---|
| Deterministic `/codec/keys` and multi-key JWKS ordering | Not implemented. `ListKeyIDs`, `PublicKeys`, docs, and existing tests promise membership but no order; sorting would unexpectedly change serialized bytes. Single-key field/body order is now frozen. |
| Ignored `json.Encoder.Encode` errors | Not implemented. All response values are JSON-encodable, while writer failures occur after headers are committed. No documented/tested failed-writer status or body exists, and buffering or fallback rendering would change HTTP behavior. |

## Out of Scope

Sibling repositories, exported API/ABI redesign, route additions, cryptographic hardening, attestation-format changes, environment/config renaming, dependency changes, generated artifacts, staging, commits, pushes, merges, and safety-stash mutation were not undertaken.

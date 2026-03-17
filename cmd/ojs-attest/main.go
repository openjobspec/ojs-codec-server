// Command ojs-attest is the M1/P1 prototype CLI for the ext_attest
// envelope key (RFC-0010-ext-attest.md). Three subcommands:
//
//   ojs-attest keygen  -seed seed.bin -pub pub.bin
//   ojs-attest sign    -seed seed.bin -key-id <id> -input args.json [-output out.json] [-document doc.bin]
//                      [-attest-type signature-only]
//   ojs-attest verify  -pub pub.bin -evidence evidence.json
//
// The wire shape of the emitted "evidence" file is exactly the
// ext_attest envelope-key payload defined by RFC-0010, so the same JSON
// can be embedded under "ext_attest" in any OJS envelope unchanged.
//
// This is the auditor-facing companion to ctn-submit: a partner uses
// ojs-attest sign to attach attestation to a job result, and any
// downstream verifier uses ojs-attest verify (or any compatible
// implementation) to confirm provenance.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const version = "0.1.0-p1"

// AttestationEvidence is duplicated from ojs-conformance/lib/attestation.go
// on purpose: each module in this multi-repo org is independently
// versioned, so cross-module dependencies are deliberately avoided in
// CLIs. The validator and verifier MUST stay byte-compatible with
// ojs-conformance/lib; that's enforced by RFC-0010 + golden tests in
// each module.
type AttestationEvidence struct {
	Version      int    `json:"v"`
	Algorithm    string `json:"alg"`
	Type         string `json:"type"`
	KeyID        string `json:"key_id"`
	InputDigest  string `json:"input_digest"`
	OutputDigest string `json:"output_digest,omitempty"`
	Document     string `json:"document,omitempty"`
	Signature    string `json:"signature"`
	SignedAt     string `json:"signed_at"`
}

var knownTypes = map[string]struct{}{
	"signature-only": {},
	"aws-nitro":      {},
	"intel-tdx":      {},
	"amd-sev-snp":    {},
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		fmt.Println("ojs-attest", version)
	case "keygen":
		if err := keygen(os.Args[2:]); err != nil {
			fail(err)
		}
	case "sign":
		if err := sign(os.Args[2:]); err != nil {
			fail(err)
		}
	case "verify":
		if err := verify(os.Args[2:]); err != nil {
			fail(err)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ojs-attest <keygen|sign|verify|version> [flags]")
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "ojs-attest:", err)
	os.Exit(1)
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	seedPath := fs.String("seed", "", "path to write the 32-byte ed25519 seed")
	pubPath := fs.String("pub", "", "path to write the 32-byte ed25519 public key")
	_ = fs.Parse(args)
	if *seedPath == "" || *pubPath == "" {
		return errors.New("keygen: -seed and -pub required")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*seedPath, priv.Seed(), 0600); err != nil {
		return fmt.Errorf("write seed: %w", err)
	}
	if err := os.WriteFile(*pubPath, pub, 0644); err != nil {
		return fmt.Errorf("write pub: %w", err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s (32 bytes seed, mode 0600) and %s (%d bytes pub)\n",
		*seedPath, *pubPath, len(pub))
	return nil
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	seedPath := fs.String("seed", "", "ed25519 seed file (32 bytes)")
	keyID := fs.String("key-id", "", "submitter key id (e.g. did:web:...)")
	inputPath := fs.String("input", "", "path to input JSON (job args/meta), - for stdin")
	outputPath := fs.String("output", "", "optional path to output JSON (job result)")
	docPath := fs.String("document", "", "optional path to attestation document blob")
	attestType := fs.String("attest-type", "signature-only", "attestation type: signature-only|aws-nitro|intel-tdx|amd-sev-snp")
	_ = fs.Parse(args)

	if *seedPath == "" || *keyID == "" || *inputPath == "" {
		return errors.New("sign: -seed, -key-id, -input required")
	}
	if _, ok := knownTypes[*attestType]; !ok {
		return fmt.Errorf("sign: unknown -attest-type %q", *attestType)
	}
	if *attestType != "signature-only" && *docPath == "" {
		return fmt.Errorf("sign: attest-type %q requires -document", *attestType)
	}

	seed, err := os.ReadFile(*seedPath)
	if err != nil {
		return fmt.Errorf("read seed: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return fmt.Errorf("seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)

	inputBytes, err := readPath(*inputPath)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}
	inputDigest, err := canonicalDigest(inputBytes)
	if err != nil {
		return fmt.Errorf("input digest: %w", err)
	}

	var outputDigest string
	if *outputPath != "" {
		outBytes, err := os.ReadFile(*outputPath)
		if err != nil {
			return fmt.Errorf("read output: %w", err)
		}
		d, err := canonicalDigest(outBytes)
		if err != nil {
			return fmt.Errorf("output digest: %w", err)
		}
		outputDigest = d
	}

	var doc []byte
	if *docPath != "" {
		doc, err = os.ReadFile(*docPath)
		if err != nil {
			return fmt.Errorf("read document: %w", err)
		}
	}

	msg := signingPayload(inputDigest, outputDigest, doc)
	sig := ed25519.Sign(priv, msg)

	ev := AttestationEvidence{
		Version:      1,
		Algorithm:    "ed25519",
		Type:         *attestType,
		KeyID:        *keyID,
		InputDigest:  inputDigest,
		OutputDigest: outputDigest,
		Document:     base64.StdEncoding.EncodeToString(doc),
		Signature:    base64.StdEncoding.EncodeToString(sig),
		SignedAt:     time.Now().UTC().Format(time.RFC3339),
	}
	if doc == nil {
		ev.Document = ""
	}
	out, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	pubPath := fs.String("pub", "", "ed25519 public key file (32 bytes)")
	evPath := fs.String("evidence", "", "ext_attest evidence JSON, - for stdin")
	freshness := fs.Duration("freshness", 24*time.Hour, "max age of signed_at; 0 disables")
	_ = fs.Parse(args)

	if *pubPath == "" || *evPath == "" {
		return errors.New("verify: -pub and -evidence required")
	}
	pub, err := os.ReadFile(*pubPath)
	if err != nil {
		return fmt.Errorf("read pub: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("pub must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	raw, err := readPath(*evPath)
	if err != nil {
		return fmt.Errorf("read evidence: %w", err)
	}
	var ev AttestationEvidence
	if err := json.Unmarshal(raw, &ev); err != nil {
		return fmt.Errorf("parse evidence: %w", err)
	}
	if err := ev.validate(); err != nil {
		return err
	}
	if ev.Algorithm != "ed25519" {
		return fmt.Errorf("verify: algorithm %q not supported by P1 verifier", ev.Algorithm)
	}
	if ev.Type != "signature-only" && ev.Document == "" {
		return fmt.Errorf("verify: type %q requires non-empty document", ev.Type)
	}
	signedAt, _ := time.Parse(time.RFC3339, ev.SignedAt)
	if *freshness > 0 && time.Since(signedAt) > *freshness {
		return fmt.Errorf("verify: signed_at %s exceeds freshness window %s", ev.SignedAt, *freshness)
	}
	sig, _ := base64.StdEncoding.DecodeString(ev.Signature)
	doc, _ := base64.StdEncoding.DecodeString(ev.Document)
	if !ed25519.Verify(ed25519.PublicKey(pub), signingPayload(ev.InputDigest, ev.OutputDigest, doc), sig) {
		return errors.New("verify: signature invalid")
	}
	// M1/P2: structural validation of TEE quote/report headers when
	// the evidence claims a TEE-bound type. Catches truncated /
	// malformed / wrong-TEE documents that pass the ed25519 check
	// trivially. Full quote-signature verification (Intel QvL / AMD
	// SNP cert chain) is M1/P3.
	if ev.Type == "intel-tdx" || ev.Type == "amd-sev-snp" || ev.Type == "aws-nitro" {
		info, err := validateTEEDocument(ev.Type, doc)
		if err != nil {
			return fmt.Errorf("verify: tee document: %w", err)
		}
		fmt.Println("OK", ev.KeyID, ev.SignedAt, "tee="+info.Type, fmt.Sprintf("ver=%d", info.Version))
		return nil
	}
	fmt.Println("OK", ev.KeyID, ev.SignedAt)
	return nil
}

func (e *AttestationEvidence) validate() error {
	if e.Version != 1 {
		return fmt.Errorf("validate: unsupported version %d", e.Version)
	}
	if _, ok := knownTypes[e.Type]; !ok {
		return fmt.Errorf("validate: unknown type %q", e.Type)
	}
	if e.KeyID == "" {
		return errors.New("validate: missing key_id")
	}
	if !strings.HasPrefix(e.InputDigest, "sha256:") || len(e.InputDigest) != len("sha256:")+64 {
		return fmt.Errorf("validate: malformed input_digest %q", e.InputDigest)
	}
	if e.OutputDigest != "" && (!strings.HasPrefix(e.OutputDigest, "sha256:") || len(e.OutputDigest) != len("sha256:")+64) {
		return fmt.Errorf("validate: malformed output_digest %q", e.OutputDigest)
	}
	if _, err := base64.StdEncoding.DecodeString(e.Signature); err != nil {
		return fmt.Errorf("validate: signature not base64: %w", err)
	}
	if e.Document != "" {
		if _, err := base64.StdEncoding.DecodeString(e.Document); err != nil {
			return fmt.Errorf("validate: document not base64: %w", err)
		}
	}
	if _, err := time.Parse(time.RFC3339, e.SignedAt); err != nil {
		return fmt.Errorf("validate: signed_at not RFC 3339: %w", err)
	}
	return nil
}

func canonicalDigest(raw []byte) (string, error) {
	var probe any
	if err := json.Unmarshal(raw, &probe); err != nil {
		return "", err
	}
	canon, err := json.Marshal(probe)
	if err != nil {
		return "", err
	}
	d := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(d[:]), nil
}

// signingPayload mirrors ojs-conformance/lib.SigningPayload exactly.
func signingPayload(input, output string, document []byte) []byte {
	const sep = 0x1F
	out := make([]byte, 0, len(input)+1+len(output)+1+len(document))
	out = append(out, []byte(input)...)
	out = append(out, sep)
	out = append(out, []byte(output)...)
	out = append(out, sep)
	out = append(out, document...)
	return out
}

func readPath(p string) ([]byte, error) {
	if p == "-" {
		return io.ReadAll(io.LimitReader(os.Stdin, 4<<20))
	}
	return os.ReadFile(p)
}

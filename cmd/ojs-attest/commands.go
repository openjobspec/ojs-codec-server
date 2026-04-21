package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

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
		outputDigest, err = canonicalDigest(outBytes)
		if err != nil {
			return fmt.Errorf("output digest: %w", err)
		}
	}

	var doc []byte
	if *docPath != "" {
		doc, err = os.ReadFile(*docPath)
		if err != nil {
			return fmt.Errorf("read document: %w", err)
		}
	}

	signer := attestationEvidenceSigner{
		privateKey: ed25519.NewKeyFromSeed(seed),
		keyID:      *keyID,
		attestType: *attestType,
	}
	ev := signer.Sign(inputDigest, outputDigest, doc)
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

	verifier := attestationEvidenceVerifier{
		publicKey: ed25519.PublicKey(pub),
		freshness: *freshness,
	}
	result, err := verifier.Verify(ev)
	if err != nil {
		return err
	}
	if result.tee != nil {
		fmt.Println("OK", ev.KeyID, ev.SignedAt, "tee="+result.tee.Type, fmt.Sprintf("ver=%d", result.tee.Version))
		return nil
	}
	fmt.Println("OK", ev.KeyID, ev.SignedAt)
	return nil
}

func readPath(p string) ([]byte, error) {
	if p == "-" {
		return io.ReadAll(io.LimitReader(os.Stdin, 4<<20))
	}
	return os.ReadFile(p)
}

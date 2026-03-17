package main

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func buildBin(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "ojs-attest")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func runOK(t *testing.T, bin string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", bin, args, err, out)
	}
	return out
}

func runErr(t *testing.T, bin string, args ...string) ([]byte, error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()
	return out, err
}

func TestEndToEndKeygenSignVerify(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end in -short mode")
	}
	bin := buildBin(t)
	dir := t.TempDir()
	seed := filepath.Join(dir, "seed.bin")
	pub := filepath.Join(dir, "pub.bin")
	input := filepath.Join(dir, "args.json")
	output := filepath.Join(dir, "out.json")
	evidence := filepath.Join(dir, "evidence.json")

	if err := os.WriteFile(input, []byte(`["arg1","arg2",{"k":"v"}]`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte(`{"ok":true,"value":42}`), 0644); err != nil {
		t.Fatal(err)
	}

	runOK(t, bin, "keygen", "-seed", seed, "-pub", pub)

	// Verify the seed actually produced a valid key.
	seedBytes, _ := os.ReadFile(seed)
	if len(seedBytes) != ed25519.SeedSize {
		t.Fatalf("seed size: %d", len(seedBytes))
	}
	pubBytes, _ := os.ReadFile(pub)
	if len(pubBytes) != ed25519.PublicKeySize {
		t.Fatalf("pub size: %d", len(pubBytes))
	}
	derived := ed25519.NewKeyFromSeed(seedBytes).Public().(ed25519.PublicKey)
	for i := range derived {
		if derived[i] != pubBytes[i] {
			t.Fatalf("seed and pub disagree at byte %d", i)
		}
	}

	raw := runOK(t, bin, "sign",
		"-seed", seed,
		"-key-id", "did:web:test:keys:p1",
		"-input", input,
		"-output", output,
	)
	if err := os.WriteFile(evidence, raw, 0644); err != nil {
		t.Fatal(err)
	}

	// Sanity: the evidence parses as the documented schema.
	var ev AttestationEvidence
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatalf("evidence parse: %v\n%s", err, raw)
	}
	if ev.Algorithm != "ed25519" || ev.KeyID != "did:web:test:keys:p1" {
		t.Fatalf("evidence fields: %+v", ev)
	}

	out := runOK(t, bin, "verify", "-pub", pub, "-evidence", evidence)
	if !strings.HasPrefix(string(out), "OK ") {
		t.Fatalf("verify expected OK, got: %s", out)
	}
}

func TestVerifyRejectsTamperedDigest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short mode")
	}
	bin := buildBin(t)
	dir := t.TempDir()
	seed := filepath.Join(dir, "seed.bin")
	pub := filepath.Join(dir, "pub.bin")
	input := filepath.Join(dir, "args.json")
	evidence := filepath.Join(dir, "evidence.json")

	os.WriteFile(input, []byte(`["a"]`), 0644)
	runOK(t, bin, "keygen", "-seed", seed, "-pub", pub)
	raw := runOK(t, bin, "sign", "-seed", seed, "-key-id", "k1", "-input", input)

	var ev AttestationEvidence
	json.Unmarshal(raw, &ev)
	// Flip the input digest to something else valid-looking.
	ev.InputDigest = "sha256:" + strings.Repeat("0", 64)
	tampered, _ := json.Marshal(ev)
	os.WriteFile(evidence, tampered, 0644)

	out, err := runErr(t, bin, "verify", "-pub", pub, "-evidence", evidence)
	if err == nil {
		t.Fatalf("expected verify to fail; output: %s", out)
	}
}

func TestSignRejectsMissingFlags(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	bin := buildBin(t)
	out, err := runErr(t, bin, "sign", "-key-id", "k1")
	if err == nil {
		t.Fatalf("expected error; output: %s", out)
	}
}

func TestSignRejectsHardwareTypeWithoutDocument(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	bin := buildBin(t)
	dir := t.TempDir()
	seed := filepath.Join(dir, "seed.bin")
	pub := filepath.Join(dir, "pub.bin")
	input := filepath.Join(dir, "args.json")
	os.WriteFile(input, []byte(`[]`), 0644)
	runOK(t, bin, "keygen", "-seed", seed, "-pub", pub)
	out, err := runErr(t, bin, "sign",
		"-seed", seed, "-key-id", "k1", "-input", input,
		"-attest-type", "aws-nitro")
	if err == nil {
		t.Fatalf("expected hardware-type-without-doc rejection; got: %s", out)
	}
}

func TestVersion(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	bin := buildBin(t)
	out := runOK(t, bin, "version")
	if !strings.Contains(string(out), "ojs-attest") {
		t.Fatalf("version output: %s", out)
	}
}

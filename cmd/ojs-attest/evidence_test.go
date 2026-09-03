package main

import (
	"bytes"
	"testing"
)

func TestSigningPayloadWireBytes(t *testing.T) {
	got := signingPayload(
		"sha256:input",
		"sha256:output",
		[]byte{0x00, 0x1f, 0xff},
	)
	want := []byte("sha256:input\x1fsha256:output\x1f\x00\x1f\xff")

	if !bytes.Equal(got, want) {
		t.Fatalf("signing payload = %x, want %x", got, want)
	}
}

func TestCanonicalDigestIgnoresJSONFormatting(t *testing.T) {
	compact, err := canonicalDigest([]byte(`{"a":1,"b":[true,null]}`))
	if err != nil {
		t.Fatal(err)
	}
	formatted, err := canonicalDigest([]byte("{\n  \"b\": [true, null],\n  \"a\": 1\n}\n"))
	if err != nil {
		t.Fatal(err)
	}

	if compact != formatted {
		t.Fatalf("canonical digests differ: %q != %q", compact, formatted)
	}
}

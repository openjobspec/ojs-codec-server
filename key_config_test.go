package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestLoadKeysSelectsFirstNonEmptyMultiKeyEntry(t *testing.T) {
	t.Setenv("OJS_CODEC_KEY", "")
	t.Setenv("OJS_CODEC_KEY_ID", "")
	t.Setenv("OJS_CODEC_KEYS", " ,\t, later:"+strings.Repeat("01", 32)+",newest:"+strings.Repeat("02", 32))

	provider, err := loadKeys()
	if err != nil {
		t.Fatal(err)
	}
	if got := provider.CurrentKeyID(); got != "later" {
		t.Fatalf("current key ID = %q, want %q", got, "later")
	}
	if got := keyIDSet(provider.ListKeyIDs()); !got["later"] || !got["newest"] || len(got) != 2 {
		t.Fatalf("loaded key IDs = %v", got)
	}
}

func TestLoadKeysPreservesMultiKeyOrderAndDuplicateSemantics(t *testing.T) {
	t.Setenv("OJS_CODEC_KEY", "")
	t.Setenv("OJS_CODEC_KEY_ID", "")
	t.Setenv("OJS_CODEC_KEYS", "first:"+strings.Repeat("01", 32)+",second:"+strings.Repeat("02", 32)+",first:"+strings.Repeat("03", 32))

	provider, err := loadKeys()
	if err != nil {
		t.Fatal(err)
	}
	if got := provider.CurrentKeyID(); got != "first" {
		t.Fatalf("current key ID = %q, want first", got)
	}
	key, err := provider.GetKey("first")
	if err != nil {
		t.Fatal(err)
	}
	if want := bytes.Repeat([]byte{0x03}, 32); !bytes.Equal(key, want) {
		t.Fatalf("duplicate key bytes = %x, want %x", key, want)
	}
}

func TestLoadKeysPreservesSingleKeyAsCurrent(t *testing.T) {
	t.Setenv("OJS_CODEC_KEY", strings.Repeat("04", 32))
	t.Setenv("OJS_CODEC_KEY_ID", "single")
	t.Setenv("OJS_CODEC_KEYS", ",older:"+strings.Repeat("05", 32))

	provider, err := loadKeys()
	if err != nil {
		t.Fatal(err)
	}
	if got := provider.CurrentKeyID(); got != "single" {
		t.Fatalf("current key ID = %q, want single", got)
	}
	if got := keyIDSet(provider.ListKeyIDs()); !got["single"] || !got["older"] || len(got) != 2 {
		t.Fatalf("loaded key IDs = %v", got)
	}
}

func TestLoadKeysPreservesAllEmptyMultiKeyBehavior(t *testing.T) {
	t.Setenv("OJS_CODEC_KEY", "")
	t.Setenv("OJS_CODEC_KEY_ID", "")
	t.Setenv("OJS_CODEC_KEYS", ", ,\t")

	provider, err := loadKeys()
	if err != nil {
		t.Fatal(err)
	}
	if got := provider.CurrentKeyID(); got != "" {
		t.Fatalf("current key ID = %q, want empty", got)
	}
	if got := provider.ListKeyIDs(); len(got) != 0 {
		t.Fatalf("loaded key IDs = %v, want none", got)
	}
}

func TestLoadKeysPreservesEmptyIDEntrySelection(t *testing.T) {
	t.Setenv("OJS_CODEC_KEY", "")
	t.Setenv("OJS_CODEC_KEY_ID", "")
	t.Setenv("OJS_CODEC_KEYS", ":"+strings.Repeat("06", 32)+",later:"+strings.Repeat("07", 32))

	provider, err := loadKeys()
	if err != nil {
		t.Fatal(err)
	}
	if got := provider.CurrentKeyID(); got != "" {
		t.Fatalf("current key ID = %q, want empty ID from first loaded entry", got)
	}
	if _, err := provider.GetKey(""); err != nil {
		t.Fatalf("empty-ID key was not retained: %v", err)
	}
}

func TestLoadKeysPreservesMultiKeyErrors(t *testing.T) {
	tests := []struct {
		name      string
		multiKeys string
		want      string
	}{
		{
			name:      "invalid format after leading empty",
			multiKeys: ",bad",
			want:      `OJS_CODEC_KEYS: invalid format "bad" (expected id:hexkey)`,
		},
		{
			name:      "invalid hex",
			multiKeys: "key:zz",
			want:      `OJS_CODEC_KEYS: key "key": invalid hex: encoding/hex: invalid byte: U+007A 'z'`,
		},
		{
			name:      "invalid size",
			multiKeys: "key:00",
			want:      `OJS_CODEC_KEYS: key "key" must be 32 bytes for AES-256, got 1`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("OJS_CODEC_KEY", "")
			t.Setenv("OJS_CODEC_KEY_ID", "")
			t.Setenv("OJS_CODEC_KEYS", tt.multiKeys)

			_, err := loadKeys()
			if got := errorString(err); got != tt.want {
				t.Fatalf("error = %q, want %q", got, tt.want)
			}
		})
	}
}

func keyIDSet(ids []string) map[string]bool {
	set := make(map[string]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return set
}

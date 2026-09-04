package crypto

import (
	"bytes"
	"testing"
)

func TestRandomBytes(t *testing.T) {
	a, err := RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}
	b, err := RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}
	if len(a) != 32 || len(b) != 32 {
		t.Fatalf("wrong lengths %d %d", len(a), len(b))
	}
	if bytes.Equal(a, b) {
		t.Fatal("two random draws are equal — CSPRNG broken?")
	}
}

func TestDeriveKeySeparation(t *testing.T) {
	secret, _ := RandomBytes(32)
	salt, _ := RandomBytes(32)
	k1, err := DeriveKey(secret, salt, "purpose-one", 32)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := DeriveKey(secret, salt, "purpose-two", 32)
	if err != nil {
		t.Fatal(err)
	}
	k3, err := DeriveKey(secret, salt, "purpose-one", 32)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k1, k2) {
		t.Fatal("different info labels produced the same key — no key separation")
	}
	if !bytes.Equal(k1, k3) {
		t.Fatal("same inputs produced different keys — HKDF not deterministic")
	}
	if len(k1) != 32 {
		t.Fatalf("wrong key length %d", len(k1))
	}
}

func TestDeriveKeyEmptySecret(t *testing.T) {
	if _, err := DeriveKey(nil, nil, "x", 32); err == nil {
		t.Fatal("expected error for empty secret")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	key, _ := RandomKey()
	aad := []byte("header-bytes")
	pt := []byte("hello secure world")
	blob, err := Seal(key, aad, pt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(key, aad, blob)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatal("round trip mismatch")
	}
}

func TestSealRandomNonce(t *testing.T) {
	key, _ := RandomKey()
	pt := []byte("same plaintext")
	a, _ := Seal(key, nil, pt)
	b, _ := Seal(key, nil, pt)
	if bytes.Equal(a, b) {
		t.Fatal("identical ciphertexts for identical plaintexts — nonce reuse?")
	}
}

func TestOpenTamperedCiphertext(t *testing.T) {
	key, _ := RandomKey()
	blob, _ := Seal(key, nil, []byte("data"))
	// Flip a bit in the ciphertext body.
	blob[len(blob)-1] ^= 0x01
	if _, err := Open(key, nil, blob); err != ErrDecrypt {
		t.Fatalf("expected ErrDecrypt for tampered ciphertext, got %v", err)
	}
}

func TestOpenTamperedNonce(t *testing.T) {
	key, _ := RandomKey()
	blob, _ := Seal(key, nil, []byte("data"))
	blob[0] ^= 0xff
	if _, err := Open(key, nil, blob); err != ErrDecrypt {
		t.Fatalf("expected ErrDecrypt for tampered nonce, got %v", err)
	}
}

func TestOpenWrongAAD(t *testing.T) {
	key, _ := RandomKey()
	blob, _ := Seal(key, []byte("aad-1"), []byte("data"))
	if _, err := Open(key, []byte("aad-2"), blob); err != ErrDecrypt {
		t.Fatalf("expected ErrDecrypt for wrong AAD, got %v", err)
	}
}

func TestOpenWrongKey(t *testing.T) {
	k1, _ := RandomKey()
	k2, _ := RandomKey()
	blob, _ := Seal(k1, nil, []byte("data"))
	if _, err := Open(k2, nil, blob); err != ErrDecrypt {
		t.Fatalf("expected ErrDecrypt for wrong key, got %v", err)
	}
}

func TestOpenTruncated(t *testing.T) {
	key, _ := RandomKey()
	if _, err := Open(key, nil, []byte("short")); err != ErrDecrypt {
		t.Fatalf("expected ErrDecrypt for truncated blob, got %v", err)
	}
}

func TestInvalidKeySize(t *testing.T) {
	if _, err := Seal([]byte("too short"), nil, nil); err == nil {
		t.Fatal("expected error for invalid key size")
	}
}

func TestZeroise(t *testing.T) {
	b := []byte("secret key material here......")
	Zeroise(b)
	if !bytes.Equal(b, make([]byte, len(b))) {
		t.Fatal("Zeroise did not clear the slice")
	}
}

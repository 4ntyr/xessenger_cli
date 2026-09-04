package identity

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateAndFingerprint(t *testing.T) {
	id, err := Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	if !id.HasPrivateKey() {
		t.Fatal("generated identity has no private key")
	}
	fp := id.Fingerprint()
	if !strings.HasPrefix(fp, "SHA256: ") {
		t.Fatalf("fingerprint has wrong format: %q", fp)
	}
	// 32 bytes → 32 "XX" groups separated by colons.
	if got := len(strings.Split(strings.TrimPrefix(fp, "SHA256: "), ":")); got != 32 {
		t.Fatalf("fingerprint has %d groups, want 32", got)
	}

	other, _ := Generate("bob")
	if id.Fingerprint() == other.Fingerprint() {
		t.Fatal("two identities share a fingerprint")
	}
}

func TestGenerateEmptyName(t *testing.T) {
	if _, err := Generate("  "); err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestSignVerify(t *testing.T) {
	id, _ := Generate("alice")
	msg := []byte("transcript hash")
	sig, err := id.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !id.Verify(msg, sig) {
		t.Fatal("valid signature rejected")
	}
	if id.Verify([]byte("other message"), sig) {
		t.Fatal("signature accepted for different message")
	}
	other, _ := Generate("mallory")
	if other.Verify(msg, sig) {
		t.Fatal("signature accepted under wrong key")
	}
	// Tampered signature.
	sig[0] ^= 0xff
	if id.Verify(msg, sig) {
		t.Fatal("tampered signature accepted")
	}
}

func TestSignWithoutPrivateKey(t *testing.T) {
	id, _ := Generate("alice")
	pubOnly := FromPublicKey("alice", id.PublicKey())
	if pubOnly.HasPrivateKey() {
		t.Fatal("public-only identity claims a private key")
	}
	if _, err := pubOnly.Sign([]byte("x")); err == nil {
		t.Fatal("expected signing error without private key")
	}
}

func TestSaveLoadEncrypted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.key")
	id, _ := Generate("alice")
	if err := id.Save(path, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}

	// File permissions must be owner-only.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("identity file mode = %o, want 0600", perm)
	}

	// The raw file must not contain the private key bytes.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, id.priv) {
		t.Fatal("private key stored in plaintext on disk")
	}

	loaded, err := Load(path, "correct horse battery staple")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Name != "alice" || !loaded.PublicKey().Equal(id.PublicKey()) {
		t.Fatal("loaded identity mismatch")
	}
	// Round-tripped key must still sign.
	sig, err := loaded.Sign([]byte("ping"))
	if err != nil || !loaded.Verify([]byte("ping"), sig) {
		t.Fatal("loaded identity cannot sign/verify")
	}
}

func TestLoadWrongPassphrase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.key")
	id, _ := Generate("alice")
	if err := id.Save(path, "right"); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, "wrong"); err == nil {
		t.Fatal("expected error for wrong passphrase")
	}
	if _, err := Load(path, ""); err == nil {
		t.Fatal("expected error for missing passphrase")
	}
}

func TestSaveEmptyPassphraseRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.key")
	id, _ := Generate("alice")
	if err := id.Save(path, ""); err == nil {
		t.Fatal("empty passphrase must be refused by Save")
	}
}

func TestSaveLoadInsecureDevMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dev.key")
	id, _ := Generate("dev")
	if err := id.SaveInsecure(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path, "")
	if err != nil {
		t.Fatalf("Load insecure: %v", err)
	}
	if !loaded.PublicKey().Equal(id.PublicKey()) {
		t.Fatal("insecure round trip mismatch")
	}
	if _, err := Load(path, "nonempty"); err == nil {
		t.Fatal("expected error when passphrase given for unencrypted file")
	}
}

func TestLoadCorruptedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.key")
	id, _ := Generate("alice")
	if err := id.Save(path, "pw"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	raw[len(raw)-1] ^= 0xff // corrupt the ciphertext/tag
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, "pw"); err == nil {
		t.Fatal("expected error for corrupted file")
	}
}

func TestLoadBadVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.key")
	if err := os.WriteFile(path, []byte{99, 0, 1, 2, 3}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, "pw"); err == nil {
		t.Fatal("expected error for bad version")
	}
}

func TestMarshalBinaryRoundTrip(t *testing.T) {
	id, _ := Generate("alice")
	buf := id.MarshalBinary()
	n := int(buf[0])<<8 | int(buf[1])
	name := string(buf[2 : 2+n])
	pub := ed25519.PublicKey(buf[2+n:])
	if name != "alice" || !pub.Equal(id.PublicKey()) {
		t.Fatal("MarshalBinary round trip mismatch")
	}
}

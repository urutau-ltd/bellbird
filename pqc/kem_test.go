package pqc

import (
	"bytes"
	"testing"
)

func TestGenerateKeyPairSizes(t *testing.T) {
	t.Parallel()

	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	if len(kp.PublicKey) != Sizes.PublicTotal {
		t.Fatalf("public key size = %d, want %d", len(kp.PublicKey), Sizes.PublicTotal)
	}
	if len(kp.PrivateKey) != Sizes.PrivateTotal {
		t.Fatalf("private key size = %d, want %d", len(kp.PrivateKey), Sizes.PrivateTotal)
	}
}

func TestEncapsulateDecapsulateRoundTrip(t *testing.T) {
	t.Parallel()

	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	ct, ssClient, err := Encapsulate(kp.PublicKey)
	if err != nil {
		t.Fatalf("Encapsulate() error = %v", err)
	}

	ssRelay, err := Decapsulate(kp.PrivateKey, ct)
	if err != nil {
		t.Fatalf("Decapsulate() error = %v", err)
	}

	if !bytes.Equal(ssClient, ssRelay) {
		t.Fatal("shared secrets do not match")
	}
}

func TestEncapsulateRejectsWrongPubKeySize(t *testing.T) {
	t.Parallel()

	if _, _, err := Encapsulate([]byte{1, 2, 3}); err == nil {
		t.Fatal("Encapsulate() expected error for wrong pubkey size, got nil")
	}
}

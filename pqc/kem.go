// Package pqc implements a hybrid post-quantum ke encapsulation mechanism
// combining ML-KEM-768 (NIST FIPS 203) with X25519.
//
// Security model:
//   - If ML-KEM-768 is broken (unknown flaw): X25519 acts as classic security.
//   - If X25519 is broken by a quantum computer: ML-KEM-768 maintains PQ sec.
//   - Session key = HKDF(mlkem_shared_secret || x25519_shared_secret, "bellbird-v1")
package pqc

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

var scheme kem.Scheme = mlkem768.Scheme()

// Sizes holds the byte lengths of all key material.
// Computed from the scheme at init time — never hardcode these.
var Sizes = struct {
	MLKEMPublic  int // 1184
	MLKEMPrivate int // 2400
	MLKEMCipher  int // 1088
	X25519       int // 32
	PublicTotal  int // MLKEMPublic + X25519
	PrivateTotal int // MLKEMPrivate + X25519
	CipherTotal  int // MLKEMCipher + X25519 (ephemeral pub)
}{
	MLKEMPublic:  scheme.PublicKeySize(),
	MLKEMPrivate: scheme.PrivateKeySize(),
	MLKEMCipher:  scheme.CiphertextSize(),
	X25519:       32,
	PublicTotal:  scheme.PublicKeySize() + 32,
	PrivateTotal: scheme.PrivateKeySize() + 32,
	CipherTotal:  scheme.CiphertextSize() + 32,
}

// KeyPair holds hybrid public and private key material.
//
//	PublicKey  = mlkem_pub(1184)  || x25519_pub(32)   = 1216 bytes
//	PrivateKey = mlkem_priv(2400) || x25519_priv(32)  = 2432 bytes
type KeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
}

// GenerateKeyPair creates a fresh hybrid ML-KEM-768 + X25519 key pair.
func GenerateKeyPair() (*KeyPair, error) {
	// ML-KEM-768
	pk, sk, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("mlkem keygen: %w", err)
	}
	mlkemPub, err := pk.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("mlkem marshal pub: %w", err)
	}
	mlkemPriv, err := sk.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("mlkem marshal priv: %w", err)
	}

	// X25519
	var x25519Priv [32]byte
	if _, err := rand.Read(x25519Priv[:]); err != nil {
		return nil, fmt.Errorf("x25519 entropy: %w", err)
	}
	x25519Pub, err := curve25519.X25519(x25519Priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("x25519 derive pub: %w", err)
	}

	return &KeyPair{
		PublicKey:  append(mlkemPub, x25519Pub...),
		PrivateKey: append(mlkemPriv, x25519Priv[:]...),
	}, nil
}

// Encapsulate performs KEM encapsulation against a relay public key.
// Called by the client.
//
// Returns:
//   - ciphertext: send this to the relay (Sizes.CipherTotal bytes)
//   - sharedSecret: 32-byte session key, kept locally
func Encapsulate(pubKey []byte) (ciphertext, sharedSecret []byte, err error) {
	if len(pubKey) != Sizes.PublicTotal {
		return nil, nil, fmt.Errorf("pubkey: got %d bytes, want %d", len(pubKey), Sizes.PublicTotal)
	}

	mlkemPub, err := scheme.UnmarshalBinaryPublicKey(pubKey[:Sizes.MLKEMPublic])
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshal mlkem pub: %w", err)
	}
	x25519RelayPub := pubKey[Sizes.MLKEMPublic:]

	// ML-KEM encapsulation
	mlkemCT, mlkemSS, err := scheme.Encapsulate(mlkemPub)
	if err != nil {
		return nil, nil, fmt.Errorf("mlkem encapsulate: %w", err)
	}

	// X25519 ephemeral DH
	var ephPriv [32]byte
	if _, err := rand.Read(ephPriv[:]); err != nil {
		return nil, nil, fmt.Errorf("x25519 ephemeral entropy: %w", err)
	}
	ephPub, err := curve25519.X25519(ephPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("x25519 derive ephem pub: %w", err)
	}
	x25519SS, err := curve25519.X25519(ephPriv[:], x25519RelayPub)
	if err != nil {
		return nil, nil, fmt.Errorf("x25519 dh: %w", err)
	}

	ss, err := deriveSessionKey(mlkemSS, x25519SS)
	if err != nil {
		return nil, nil, err
	}

	// ciphertext = mlkem_ct || x25519_ephemeral_pub
	return append(mlkemCT, ephPub...), ss, nil
}

// Decapsulate recovers the shared secret from a ciphertext.
// Called by the relay.
//
//   - privKey: Sizes.PrivateTotal bytes
//   - ciphertext: Sizes.CipherTotal bytes (from Encapsulate)
func Decapsulate(privKey, ciphertext []byte) ([]byte, error) {
	if len(privKey) != Sizes.PrivateTotal {
		return nil, fmt.Errorf("privkey: got %d bytes, want %d", len(privKey), Sizes.PrivateTotal)
	}
	if len(ciphertext) != Sizes.CipherTotal {
		return nil, fmt.Errorf("ciphertext: got %d bytes, want %d", len(ciphertext), Sizes.CipherTotal)
	}

	mlkemCT := ciphertext[:Sizes.MLKEMCipher]
	x25519EphPub := ciphertext[Sizes.MLKEMCipher:]

	sk, err := scheme.UnmarshalBinaryPrivateKey(privKey[:Sizes.MLKEMPrivate])
	if err != nil {
		return nil, fmt.Errorf("unmarshal mlkem priv: %w", err)
	}
	x25519Priv := privKey[Sizes.MLKEMPrivate:]

	mlkemSS, err := scheme.Decapsulate(sk, mlkemCT)
	if err != nil {
		return nil, fmt.Errorf("mlkem decapsulate: %w", err)
	}
	x25519SS, err := curve25519.X25519(x25519Priv, x25519EphPub)
	if err != nil {
		return nil, fmt.Errorf("x25519 dh: %w", err)
	}

	return deriveSessionKey(mlkemSS, x25519SS)
}

// deriveSessionKey combines both shared secrets into a 32-byte key via HKDF-SHA256.
func deriveSessionKey(mlkemSS, x25519SS []byte) ([]byte, error) {
	ikm := append(mlkemSS, x25519SS...) //nolint:gocritic
	r := hkdf.New(sha256.New, ikm, nil, []byte("bellbird-v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return key, nil
}

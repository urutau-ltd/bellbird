package proxy

import (
	"bytes"
	crand "crypto/rand"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestDirectionalKeysAreDistinctAndDeterministic(t *testing.T) {
	t.Parallel()

	session := bytes.Repeat([]byte{0x42}, 32)

	k1a, err := deriveDirectionalKey(session, clientToRelayInfo)
	if err != nil {
		t.Fatalf("deriveDirectionalKey(client->relay) error = %v", err)
	}
	k1b, err := deriveDirectionalKey(session, clientToRelayInfo)
	if err != nil {
		t.Fatalf("deriveDirectionalKey(client->relay second) error = %v", err)
	}
	k2, err := deriveDirectionalKey(session, relayToClientInfo)
	if err != nil {
		t.Fatalf("deriveDirectionalKey(relay->client) error = %v", err)
	}

	if !bytes.Equal(k1a, k1b) {
		t.Fatal("client->relay key derivation is not deterministic")
	}
	if bytes.Equal(k1a, k2) {
		t.Fatal("directional keys should be different")
	}
}

func TestDirectionalAEADRejectsWrongDirectionKey(t *testing.T) {
	t.Parallel()

	session := make([]byte, 32)
	if _, err := crand.Read(session); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}

	c2r, err := deriveDirectionalKey(session, clientToRelayInfo)
	if err != nil {
		t.Fatalf("deriveDirectionalKey(client->relay) error = %v", err)
	}
	r2c, err := deriveDirectionalKey(session, relayToClientInfo)
	if err != nil {
		t.Fatalf("deriveDirectionalKey(relay->client) error = %v", err)
	}

	clientAEAD, err := newAEAD(c2r)
	if err != nil {
		t.Fatalf("newAEAD(client) error = %v", err)
	}
	relayAEAD, err := newAEAD(r2c)
	if err != nil {
		t.Fatalf("newAEAD(relay) error = %v", err)
	}

	nonce := counterNonce(1)
	payload := []byte("hello")
	aad := make([]byte, 15)
	aad[0] = PacketData
	binary.BigEndian.PutUint16(aad[1:3], uint16(len(payload)+clientAEAD.Overhead()))
	copy(aad[3:], nonce)

	ct := clientAEAD.Seal(nil, nonce, payload, aad)

	if _, err := relayAEAD.Open(nil, nonce, ct, aad); err == nil {
		t.Fatal("relay direction key unexpectedly decrypted client ciphertext")
	}
}

func TestRelayHelloTagBindsTranscript(t *testing.T) {
	t.Parallel()

	authKey := bytes.Repeat([]byte{0x11}, 32)
	ct := []byte("kem-ciphertext")
	clientEph := bytes.Repeat([]byte{0x22}, 32)
	relayEph := bytes.Repeat([]byte{0x33}, 32)

	tag := buildRelayHelloTag(authKey, ct, clientEph, relayEph)
	if !validateRelayHelloTag(authKey, ct, clientEph, relayEph, tag) {
		t.Fatal("validateRelayHelloTag() rejected valid tag")
	}

	mutatedCT := append([]byte(nil), ct...)
	mutatedCT[0] ^= 0x01
	if validateRelayHelloTag(authKey, mutatedCT, clientEph, relayEph, tag) {
		t.Fatal("validateRelayHelloTag() accepted tag for mutated ciphertext")
	}
}

func TestDeriveSessionRootDependsOnForwardSecret(t *testing.T) {
	t.Parallel()

	authSecret := bytes.Repeat([]byte{0x44}, 32)
	fsA := bytes.Repeat([]byte{0x55}, 32)
	fsB := bytes.Repeat([]byte{0x56}, 32)

	rootA, err := deriveSessionRoot(authSecret, fsA)
	if err != nil {
		t.Fatalf("deriveSessionRoot(fsA) error = %v", err)
	}
	rootB, err := deriveSessionRoot(authSecret, fsB)
	if err != nil {
		t.Fatalf("deriveSessionRoot(fsB) error = %v", err)
	}

	if bytes.Equal(rootA, rootB) {
		t.Fatal("deriveSessionRoot() should produce different roots for different FS secrets")
	}
}

func TestNewTunnelDirectionalRoundTrip(t *testing.T) {
	t.Parallel()

	session := make([]byte, 32)
	if _, err := crand.Read(session); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}

	clientConn, relayConn := net.Pipe()
	defer clientConn.Close()
	defer relayConn.Close()
	_ = clientConn.SetDeadline(time.Now().Add(2 * time.Second))
	_ = relayConn.SetDeadline(time.Now().Add(2 * time.Second))

	clientTunnel, err := newTunnel(clientConn, session, true)
	if err != nil {
		t.Fatalf("newTunnel(client) error = %v", err)
	}
	relayTunnel, err := newTunnel(relayConn, session, false)
	if err != nil {
		t.Fatalf("newTunnel(relay) error = %v", err)
	}

	wantClientMsg := []byte("client-to-relay")
	go func() {
		_ = clientTunnel.WriteFrame(PacketData, wantClientMsg)
	}()

	pt, got, err := relayTunnel.ReadFrame()
	if err != nil {
		t.Fatalf("relayTunnel.ReadFrame() error = %v", err)
	}
	if pt != PacketData {
		t.Fatalf("relay packet type = 0x%02x, want 0x%02x", pt, PacketData)
	}
	if !bytes.Equal(got, wantClientMsg) {
		t.Fatalf("relay payload = %q, want %q", got, wantClientMsg)
	}

	wantRelayMsg := []byte("relay-to-client")
	go func() {
		_ = relayTunnel.WriteFrame(PacketData, wantRelayMsg)
	}()

	pt, got, err = clientTunnel.ReadFrame()
	if err != nil {
		t.Fatalf("clientTunnel.ReadFrame() error = %v", err)
	}
	if pt != PacketData {
		t.Fatalf("client packet type = 0x%02x, want 0x%02x", pt, PacketData)
	}
	if !bytes.Equal(got, wantRelayMsg) {
		t.Fatalf("client payload = %q, want %q", got, wantRelayMsg)
	}
}

// Package proxy implements bellbird's tunnel protocol, SOCKS5 server,
// jitter engine, and policy DSL loader.
package proxy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"codeberg.org/urutau-ltd/bellbird/pqc"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	// Encrypted application data
	PacketData byte = 0x01
	// Random noise - relay discards silently
	PacketDummy byte = 0x02
	// Keepalive
	PacketPing = 0x03
	// First frame from client: target "host:port"
	PacketConnect = 0x04
	// Optional client authentication token frame.
	PacketAuth = 0x05
)

// DefaultBlockSize is the padding block in bytes. All PacketData payloads are
// padded to a multiple of this value. Observers see uniform frame sizes on
// the wire.
const DefaultBlockSize int = 512

const (
	setupTimeout = 10 * time.Second
	dialTimeout  = 10 * time.Second
)

var (
	clientToRelayInfo = []byte("bellbird-v1 key client->relay")
	relayToClientInfo = []byte("bellbird-v1 key relay->client")
	handshakeAuthInfo = []byte("bellbird-v2 handshake-auth")
	sessionRootInfo   = []byte("bellbird-v2 session-root")
	relayHelloLabel   = []byte("bellbird-v2 relay-hello")
)

const (
	relayHelloPubLen = 32
	relayHelloTagLen = sha256.Size
	relayHelloLen    = relayHelloPubLen + relayHelloTagLen
)

// Tunnel is a PQC-encrypted, framed, authenticated connection.
//
// Wire frame format (all fields big-endian):
//
//	[type:1][enc_len:2][nonce:12][AES-256-GCM ciphertext:enc_len]
//
// AAD = frame[0:15] (type + enc_len + nonce) — modification of any header byte
// causes authentication failure.
//
// Nonce = big-endian uint64 counter (bytes 4-11), bytes 0-3 are zero.
// Strict sequential nonce checking detects replays. Client and relay use
// direction-specific keys so the same counter value is never reused under
// the same key across directions.
//
// Encrypted payload format for PacketData frames:
//
//	[orig_len:2][original_data:orig_len][padding zeros]
type Tunnel struct {
	conn        net.Conn
	sendAEAD    cipher.AEAD
	recvAEAD    cipher.AEAD
	sendCounter uint64
	recvCounter uint64
	sendMu      sync.Mutex
	recvMu      sync.Mutex
}

// NewClientTunnel dials the relay, runs the PQC handshake as initiator,
// and returns a ready-to-use Tunnel.
//
// Handshake (client side):
//  1. Generate hybrid ciphertext via pqc.Encapsulate(relayPubKey)
//  2. Generate client ephemeral X25519 keypair for FS
//  3. Send [ciphertext_len:2][ciphertext][client_eph_pub:32]
//  4. Receive [relay_eph_pub:32][relay_auth_tag:32]
//  5. Verify relay_auth_tag over transcript using KEM-auth key
//  6. Derive final session root from (KEM-auth secret || ephemeral DH)
func NewClientTunnel(relayAddr string, relayPubKey []byte) (*Tunnel, error) {
	dialer := net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: 30 * time.Second,
	}
	conn, err := dialer.Dial("tcp", relayAddr)
	if err != nil {
		return nil, fmt.Errorf("dial relay %s: %w", relayAddr, err)
	}
	if err := conn.SetDeadline(time.Now().Add(setupTimeout)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("set handshake deadline: %w", err)
	}

	ct, ss, err := pqc.Encapsulate(relayPubKey)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("pqc encapsulate: %w", err)
	}
	defer zeroBytes(ss)

	var clientEphPriv [32]byte
	if _, err := rand.Read(clientEphPriv[:]); err != nil {
		conn.Close()
		return nil, fmt.Errorf("client ephemeral entropy: %w", err)
	}
	defer zeroBytes(clientEphPriv[:])

	clientEphPub, err := curve25519.X25519(clientEphPriv[:], curve25519.Basepoint)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("client derive ephemeral pubkey: %w", err)
	}

	hdr := make([]byte, 2)
	binary.BigEndian.PutUint16(hdr, uint16(len(ct)))
	hello := make([]byte, 0, len(hdr)+len(ct)+len(clientEphPub))
	hello = append(hello, hdr...)
	hello = append(hello, ct...)
	hello = append(hello, clientEphPub...)
	if err := writeFull(conn, hello); err != nil {
		conn.Close()
		return nil, fmt.Errorf("send client hello: %w", err)
	}

	relayHello := make([]byte, relayHelloLen)
	if _, err := io.ReadFull(conn, relayHello); err != nil {
		conn.Close()
		return nil, fmt.Errorf("read relay hello: %w", err)
	}
	relayEphPub := relayHello[:relayHelloPubLen]
	relayAuthTag := relayHello[relayHelloPubLen:]

	authKey, err := deriveHandshakeAuthKey(ss)
	if err != nil {
		conn.Close()
		return nil, err
	}
	defer zeroBytes(authKey)

	if !validateRelayHelloTag(authKey, ct, clientEphPub, relayEphPub, relayAuthTag) {
		conn.Close()
		return nil, fmt.Errorf("relay authentication failed")
	}

	fsSecret, err := curve25519.X25519(clientEphPriv[:], relayEphPub)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("client ephemeral dh: %w", err)
	}
	defer zeroBytes(fsSecret)
	if isAllZero(fsSecret) {
		conn.Close()
		return nil, fmt.Errorf("client ephemeral dh produced all-zero secret")
	}

	sessionRoot, err := deriveSessionRoot(ss, fsSecret)
	if err != nil {
		conn.Close()
		return nil, err
	}
	defer zeroBytes(sessionRoot)

	t, err := newTunnel(conn, sessionRoot, true)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		t.Close()
		return nil, fmt.Errorf("clear handshake deadline: %w", err)
	}
	return t, nil
}

// NewRelayTunnel accepts an incoming TCP connection and runs the PQC
// handshake as the responder.
//
// Handshake (relay side):
//  1. Read [ciphertext_len:2][ciphertext]
//  2. Read [client_eph_pub:32]
//  3. Recover auth secret via pqc.Decapsulate(privKey, ciphertext)
//  4. Generate relay ephemeral X25519 keypair and compute ephemeral DH
//  5. Send [relay_eph_pub:32][relay_auth_tag:32]
//  6. Derive final session root from (KEM-auth secret || ephemeral DH)
func NewRelayTunnel(conn net.Conn, privKey []byte) (*Tunnel, error) {
	if err := conn.SetDeadline(time.Now().Add(setupTimeout)); err != nil {
		return nil, fmt.Errorf("set handshake deadline: %w", err)
	}

	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, fmt.Errorf("read kem len: %w", err)
	}
	ctLen := int(binary.BigEndian.Uint16(hdr))
	if ctLen != pqc.Sizes.CipherTotal {
		return nil, fmt.Errorf(
			"invalid kem ciphertext len: got %d, want %d",
			ctLen, pqc.Sizes.CipherTotal,
		)
	}

	ct := make([]byte, ctLen)
	if _, err := io.ReadFull(conn, ct); err != nil {
		return nil, fmt.Errorf("read kem ciphertext: %w", err)
	}

	clientEphPub := make([]byte, 32)
	if _, err := io.ReadFull(conn, clientEphPub); err != nil {
		return nil, fmt.Errorf("read client ephemeral pubkey: %w", err)
	}

	ss, err := pqc.Decapsulate(privKey, ct)
	if err != nil {
		return nil, fmt.Errorf("pqc decapsulate: %w", err)
	}
	defer zeroBytes(ss)

	var relayEphPriv [32]byte
	if _, err := rand.Read(relayEphPriv[:]); err != nil {
		return nil, fmt.Errorf("relay ephemeral entropy: %w", err)
	}
	defer zeroBytes(relayEphPriv[:])

	relayEphPub, err := curve25519.X25519(relayEphPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("relay derive ephemeral pubkey: %w", err)
	}

	fsSecret, err := curve25519.X25519(relayEphPriv[:], clientEphPub)
	if err != nil {
		return nil, fmt.Errorf("relay ephemeral dh: %w", err)
	}
	defer zeroBytes(fsSecret)
	if isAllZero(fsSecret) {
		return nil, fmt.Errorf("relay ephemeral dh produced all-zero secret")
	}

	authKey, err := deriveHandshakeAuthKey(ss)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(authKey)

	relayAuthTag := buildRelayHelloTag(authKey, ct, clientEphPub, relayEphPub)
	relayHello := make([]byte, 0, len(relayEphPub)+len(relayAuthTag))
	relayHello = append(relayHello, relayEphPub...)
	relayHello = append(relayHello, relayAuthTag...)
	if err := writeFull(conn, relayHello); err != nil {
		return nil, fmt.Errorf("write relay hello: %w", err)
	}

	sessionRoot, err := deriveSessionRoot(ss, fsSecret)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(sessionRoot)

	return newTunnel(conn, sessionRoot, false)
}

// WriteFrame encrypts payload and sends one frame.
// Thread-safe for concurrent writers (unlikely in practice, but safe).
func (t *Tunnel) WriteFrame(pktType byte, payload []byte) error {
	t.sendMu.Lock()
	defer t.sendMu.Unlock()

	t.sendCounter++
	nonce := counterNonce(t.sendCounter)
	encLen := len(payload) + t.sendAEAD.Overhead()
	if encLen > 0xFFFF {
		return fmt.Errorf("frame too large: encrypted payload %d bytes", encLen)
	}

	// AAD = [type:1][enc_len:2][nonce:12] — authenticated but not encrypted
	aad := make([]byte, 15)
	aad[0] = pktType
	binary.BigEndian.PutUint16(aad[1:3], uint16(encLen))
	copy(aad[3:], nonce)

	ciphertext := t.sendAEAD.Seal(
		nil,
		nonce,
		payload,
		aad)

	// wire = aad || ciphertext
	if err := writeFull(t.conn, append(aad, ciphertext...)); err != nil {
		return fmt.Errorf("write frame: %w", err)
	}
	return nil
}

// ReadFrame decrypts and returns the next frame.
// Enforces sequential nonce — any gap or replay returns an error.
// Dummy and ping frames are NOT filtered here; callers decide what
// to do with them.
func (t *Tunnel) ReadFrame() (pktType byte, payload []byte, err error) {
	t.recvMu.Lock()
	defer t.recvMu.Unlock()

	aad := make([]byte, 15) // [type:1][enc_len:2][nonce:12]
	if _, err := io.ReadFull(t.conn, aad); err != nil {
		return 0, nil, fmt.Errorf("read frame header: %w", err)
	}

	pktType = aad[0]
	encLen := int(binary.BigEndian.Uint16(aad[1:3]))
	nonce := aad[3:15]
	if encLen < t.recvAEAD.Overhead() {
		return 0, nil, fmt.Errorf("invalid encrypted payload len %d", encLen)
	}

	// Strict sequential nonce check (replay / skip detection)
	t.recvCounter++
	expected := counterNonce(t.recvCounter)
	if !bytes.Equal(nonce, expected) {
		return 0, nil, fmt.Errorf(
			"nonce mismatch at frame %d: possible replay",
			t.recvCounter,
		)
	}

	ciphertext := make([]byte, encLen)
	if _, err := io.ReadFull(t.conn, ciphertext); err != nil {
		return 0, nil, fmt.Errorf("read frame body: %w", err)
	}

	plaintext, err := t.recvAEAD.Open(
		nil,
		nonce,
		ciphertext,
		aad,
	)
	if err != nil {
		return 0, nil, fmt.Errorf(
			"aead authentication failed: %w",
			err)
	}

	return pktType, plaintext, nil
}

// Close closes the underlying TCP connection.
func (t *Tunnel) Close() error {
	return t.conn.Close()
}

// PadData encodes payload with a 2-byte length prefix and pads to targetSize.
// Format: [orig_len:2][data:orig_len][zero padding]
// targetSize must be >= len(payload)+2; if not, it is extended automatically.
func PadData(payload []byte, targetSize int) []byte {
	minSize := len(payload) + 2
	if targetSize < minSize {
		targetSize = minSize
	}
	out := make([]byte, targetSize)
	binary.BigEndian.PutUint16(out[:2], uint16(len(payload)))
	copy(out[2:], payload)
	return out
}

// UnpadData extracts the original payload from a PadData-encoded buffer.
func UnpadData(data []byte) []byte {
	if len(data) < 2 {
		return data
	}
	origLen := int(binary.BigEndian.Uint16(data[:2]))
	end := 2 + origLen
	if end > len(data) {
		return data[2:] // truncated: return what we have
	}
	return data[2:end]
}

// PadSize returns the smallest multiple
// of DefaultBlockSize that fits n+2 bytes.
func PadSize(n int) int {
	total := n + 2
	blocks := (total + DefaultBlockSize - 1) / DefaultBlockSize
	return blocks * DefaultBlockSize
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: %w", err)
	}
	return gcm, nil
}

// counterNonce builds a 12-byte AES-GCM nonce from a uint64 counter.
// Bytes 0-3 are zero; bytes 4-11 encode the counter big-endian.
func counterNonce(counter uint64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], counter)
	return n
}

func newTunnel(conn net.Conn, sessionKey []byte, isClient bool) (*Tunnel, error) {
	clientToRelayKey, err := deriveDirectionalKey(sessionKey, clientToRelayInfo)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(clientToRelayKey)

	relayToClientKey, err := deriveDirectionalKey(sessionKey, relayToClientInfo)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(relayToClientKey)

	sendKey := clientToRelayKey
	recvKey := relayToClientKey
	if !isClient {
		sendKey = relayToClientKey
		recvKey = clientToRelayKey
	}

	sendAEAD, err := newAEAD(sendKey)
	if err != nil {
		return nil, err
	}
	recvAEAD, err := newAEAD(recvKey)
	if err != nil {
		return nil, err
	}

	return &Tunnel{
		conn:     conn,
		sendAEAD: sendAEAD,
		recvAEAD: recvAEAD,
	}, nil
}

func deriveDirectionalKey(sessionKey []byte, info []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, sessionKey, nil, info)
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("hkdf directional key: %w", err)
	}
	return key, nil
}

func deriveHandshakeAuthKey(sharedSecret []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, sharedSecret, nil, handshakeAuthInfo)
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("hkdf handshake auth key: %w", err)
	}
	return key, nil
}

func deriveSessionRoot(authSecret, fsSecret []byte) ([]byte, error) {
	ikm := make([]byte, 0, len(authSecret)+len(fsSecret))
	ikm = append(ikm, authSecret...)
	ikm = append(ikm, fsSecret...)
	r := hkdf.New(sha256.New, ikm, nil, sessionRootInfo)
	root := make([]byte, 32)
	if _, err := io.ReadFull(r, root); err != nil {
		return nil, fmt.Errorf("hkdf session root: %w", err)
	}
	return root, nil
}

func buildRelayHelloTag(authKey, kemCiphertext, clientEphPub, relayEphPub []byte) []byte {
	mac := hmac.New(sha256.New, authKey)
	_, _ = mac.Write(relayHelloLabel)
	_, _ = mac.Write(kemCiphertext)
	_, _ = mac.Write(clientEphPub)
	_, _ = mac.Write(relayEphPub)
	return mac.Sum(nil)
}

func validateRelayHelloTag(authKey, kemCiphertext, clientEphPub, relayEphPub, gotTag []byte) bool {
	expectedTag := buildRelayHelloTag(authKey, kemCiphertext, clientEphPub, relayEphPub)
	return subtle.ConstantTimeCompare(expectedTag, gotTag) == 1
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func isAllZero(b []byte) bool {
	var x byte
	for _, v := range b {
		x |= v
	}
	return x == 0
}

func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

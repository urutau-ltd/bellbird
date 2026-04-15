package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

const socks5SetupTimeout = 10 * time.Second

// SOCKS5Request holds the parsed destination from a SOCKS5 CONNECT handshake.
type SOCKS5Request struct {
	// Target is the destination "host:port" string.
	Target string
	// Conn is the client connection, ready for data after the handshake reply.
	Conn net.Conn
}

// AcceptSOCKS5 performs the SOCKS5 server-side handshake on conn.
// Only CONNECT (cmd=0x01) is supported. No authentication.
//
// On success, conn is left open and the caller owns it.
// On error, conn is NOT closed — the caller should close it.
func AcceptSOCKS5(conn net.Conn) (*SOCKS5Request, error) {
	if err := conn.SetDeadline(time.Now().Add(socks5SetupTimeout)); err != nil {
		return nil, fmt.Errorf("socks5 deadline setup: %w", err)
	}

	// ── Greeting ──────────────────────────────────────────────
	// Client: [VER=5:1][NMETHODS:1][METHODS:NMETHODS]
	ver := make([]byte, 2)
	if _, err := io.ReadFull(conn, ver); err != nil {
		return nil, fmt.Errorf("socks5 greeting read: %w", err)
	}
	if ver[0] != 0x05 {
		return nil, fmt.Errorf("socks5: not SOCKS5 (ver=0x%02x)", ver[0])
	}
	methods := make([]byte, ver[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return nil, fmt.Errorf("socks5 methods read: %w", err)
	}
	if !socks5MethodOffered(methods, 0x00) {
		_ = writeFull(conn, []byte{0x05, 0xFF}) // best-effort
		return nil, fmt.Errorf("socks5: no supported auth method")
	}
	// Server: [VER=5:1][METHOD=NO_AUTH(0x00):1]
	if err := writeFull(conn, []byte{0x05, 0x00}); err != nil {
		return nil, fmt.Errorf("socks5 method reply: %w", err)
	}

	// ── Request ───────────────────────────────────────────────
	// Client: [VER=5:1][CMD:1][RSV=0:1][ATYP:1]
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, fmt.Errorf("socks5 request header: %w", err)
	}
	if hdr[1] != 0x01 { // only CONNECT
		_ = writeFull(conn, socks5Reply(0x07)) // best-effort
		return nil, fmt.Errorf("socks5: unsupported command 0x%02x (only CONNECT)", hdr[1])
	}

	var host string
	switch hdr[3] {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return nil, fmt.Errorf("socks5 IPv4 read: %w", err)
		}
		host = net.IP(b).String()
	case 0x03: // Domain name
		lenB := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenB); err != nil {
			return nil, fmt.Errorf("socks5 domain len: %w", err)
		}
		domain := make([]byte, lenB[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return nil, fmt.Errorf("socks5 domain read: %w", err)
		}
		host = string(domain)
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return nil, fmt.Errorf("socks5 IPv6 read: %w", err)
		}
		host = "[" + net.IP(b).String() + "]"
	default:
		_ = writeFull(conn, socks5Reply(0x08)) // best-effort
		return nil, fmt.Errorf("socks5: unsupported ATYP 0x%02x", hdr[3])
	}

	portB := make([]byte, 2)
	if _, err := io.ReadFull(conn, portB); err != nil {
		return nil, fmt.Errorf("socks5 port read: %w", err)
	}
	port := binary.BigEndian.Uint16(portB)
	target := fmt.Sprintf("%s:%d", host, port)

	// ── Reply: success ────────────────────────────────────────
	// [VER=5][REP=0 success][RSV=0][ATYP=1 IPv4][BND.ADDR=0.0.0.0][BND.PORT=0]
	if err := writeFull(conn, socks5Reply(0x00)); err != nil {
		return nil, fmt.Errorf("socks5 success reply: %w", err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("socks5 clear deadline: %w", err)
	}

	return &SOCKS5Request{Target: target, Conn: conn}, nil
}

// socks5Reply builds a SOCKS5 reply with the given REP byte.
// BND.ADDR and BND.PORT are zeroed (not needed for a forwarding proxy).
func socks5Reply(rep byte) []byte {
	return []byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
}

func socks5MethodOffered(methods []byte, method byte) bool {
	for _, m := range methods {
		if m == method {
			return true
		}
	}
	return false
}

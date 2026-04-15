package proxy

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestAcceptSOCKS5DomainConnect(t *testing.T) {
	t.Parallel()

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	_ = serverConn.SetDeadline(time.Now().Add(2 * time.Second))
	_ = clientConn.SetDeadline(time.Now().Add(2 * time.Second))

	reqCh := make(chan *SOCKS5Request, 1)
	errCh := make(chan error, 1)
	go func() {
		req, err := AcceptSOCKS5(serverConn)
		if err != nil {
			errCh <- err
			return
		}
		reqCh <- req
	}()

	if err := writeFull(clientConn, []byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	methodReply := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, methodReply); err != nil {
		t.Fatalf("read method reply: %v", err)
	}
	if !bytes.Equal(methodReply, []byte{0x05, 0x00}) {
		t.Fatalf("method reply = %v, want [5 0]", methodReply)
	}

	host := "example.com"
	port := uint16(443)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port))
	if err := writeFull(clientConn, req); err != nil {
		t.Fatalf("write connect request: %v", err)
	}

	reply := make([]byte, 10)
	if _, err := io.ReadFull(clientConn, reply); err != nil {
		t.Fatalf("read connect reply: %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("reply rep = 0x%02x, want 0x00", reply[1])
	}

	select {
	case err := <-errCh:
		t.Fatalf("AcceptSOCKS5() error = %v", err)
	case got := <-reqCh:
		if got.Target != "example.com:443" {
			t.Fatalf("target = %q, want %q", got.Target, "example.com:443")
		}
	}
}

func TestAcceptSOCKS5RejectsUnsupportedCommand(t *testing.T) {
	t.Parallel()

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	_ = serverConn.SetDeadline(time.Now().Add(2 * time.Second))
	_ = clientConn.SetDeadline(time.Now().Add(2 * time.Second))

	errCh := make(chan error, 1)
	go func() {
		_, err := AcceptSOCKS5(serverConn)
		errCh <- err
	}()

	if err := writeFull(clientConn, []byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	methodReply := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, methodReply); err != nil {
		t.Fatalf("read method reply: %v", err)
	}

	// CMD=0x02 (BIND) is unsupported.
	req := []byte{
		0x05, 0x02, 0x00, 0x01, // ver, cmd, rsv, atyp=IPv4
	}
	if err := writeFull(clientConn, req); err != nil {
		t.Fatalf("write request: %v", err)
	}

	reply := make([]byte, 10)
	if _, err := io.ReadFull(clientConn, reply); err != nil {
		t.Fatalf("read error reply: %v", err)
	}
	if reply[1] != 0x07 {
		t.Fatalf("reply rep = 0x%02x, want 0x07", reply[1])
	}

	if err := <-errCh; err == nil {
		t.Fatal("AcceptSOCKS5() expected error, got nil")
	}
}

func TestAcceptSOCKS5RejectsWhenNoAuthMethodOffered(t *testing.T) {
	t.Parallel()

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	_ = serverConn.SetDeadline(time.Now().Add(2 * time.Second))
	_ = clientConn.SetDeadline(time.Now().Add(2 * time.Second))

	errCh := make(chan error, 1)
	go func() {
		_, err := AcceptSOCKS5(serverConn)
		errCh <- err
	}()

	// Offer only username/password auth (0x02), no 0x00.
	if err := writeFull(clientConn, []byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}

	methodReply := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, methodReply); err != nil {
		t.Fatalf("read method reply: %v", err)
	}
	if !bytes.Equal(methodReply, []byte{0x05, 0xFF}) {
		t.Fatalf("method reply = %v, want [5 255]", methodReply)
	}

	if err := <-errCh; err == nil {
		t.Fatal("AcceptSOCKS5() expected error, got nil")
	}
}

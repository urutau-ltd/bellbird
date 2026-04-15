// Package client implements the local SOCKS5 proxy that opens PQC tunnels
// to a remote bellbird relay.
package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"

	"codeberg.org/urutau-ltd/bellbird/pqc"
	"codeberg.org/urutau-ltd/bellbird/proxy"
)

// Config holds client runtime configuration.
type Config struct {
	// RelayAddr is the reachable relay address, e.g. "relay.example:9999".
	RelayAddr string
	// RelayPubKey is the relay public key content from relay.pub.
	RelayPubKey []byte
	// ListenAddr is the local SOCKS5 bind address, e.g. ":1080".
	ListenAddr string
	// PolicyPath is the path to the zygomys policy file.
	PolicyPath string
	// AuthToken enables optional relay authentication.
	// If empty, no token frame is sent.
	AuthToken string
}

// Client is a local SOCKS5 proxy instance.
type Client struct {
	cfg    Config
	policy *proxy.Policy
}

// New validates cfg and prepares a client instance.
func New(cfg Config) (*Client, error) {
	if cfg.RelayAddr == "" {
		return nil, fmt.Errorf("client: RelayAddr is required")
	}
	if len(cfg.RelayPubKey) == 0 {
		return nil, fmt.Errorf("client: RelayPubKey is required")
	}
	if len(cfg.RelayPubKey) != pqc.Sizes.PublicTotal {
		return nil, fmt.Errorf("client: RelayPubKey must be %d bytes, got %d", pqc.Sizes.PublicTotal, len(cfg.RelayPubKey))
	}
	if cfg.ListenAddr == "" {
		return nil, fmt.Errorf("client: ListenAddr is required")
	}
	if cfg.PolicyPath == "" {
		return nil, fmt.Errorf("client: PolicyPath is required")
	}

	p, err := proxy.NewPolicy(cfg.PolicyPath)
	if err != nil {
		return nil, err
	}

	return &Client{
		cfg:    cfg,
		policy: p,
	}, nil
}

// ReloadPolicy reloads the configured policy file in-place.
func (c *Client) ReloadPolicy() error {
	return c.policy.Reload()
}

// Start begins accepting local SOCKS5 connections and forwarding each one
// through a fresh tunnel to the relay. Blocks until ctx is cancelled.
func (c *Client) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", c.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("client listen %s: %w", c.cfg.ListenAddr, err)
	}
	defer ln.Close()

	log.Printf("bellbird client: SOCKS5 listening on %s", c.cfg.ListenAddr)
	log.Printf("bellbird client: relay set to %s", c.cfg.RelayAddr)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				log.Printf("client: accept error: %v", err)
				continue
			}
		}
		go c.handleConn(ctx, conn)
	}
}

func (c *Client) handleConn(parentCtx context.Context, conn net.Conn) {
	defer conn.Close()

	req, err := proxy.AcceptSOCKS5(conn)
	if err != nil {
		log.Printf("client: socks5 handshake: %v", err)
		return
	}

	tunnel, err := proxy.NewClientTunnel(c.cfg.RelayAddr, c.cfg.RelayPubKey)
	if err != nil {
		log.Printf("client: relay tunnel: %v", err)
		return
	}
	defer tunnel.Close()

	if c.cfg.AuthToken != "" {
		if err := tunnel.WriteFrame(proxy.PacketAuth, []byte(c.cfg.AuthToken)); err != nil {
			log.Printf("client: send auth token: %v", err)
			return
		}
	}

	if err := tunnel.WriteFrame(proxy.PacketConnect, []byte(req.Target)); err != nil {
		log.Printf("client: send connect target: %v", err)
		return
	}

	jitter := proxy.NewJitter(tunnel, c.policy)
	connCtx, cancel := context.WithCancel(parentCtx)
	defer cancel()
	jitter.RunDummyInjector(connCtx)

	errCh := make(chan error, 2)

	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, rerr := req.Conn.Read(buf)
			if n > 0 {
				if werr := jitter.SendData(buf[:n]); werr != nil {
					errCh <- werr
					return
				}
			}
			if rerr != nil {
				errCh <- rerr
				return
			}
		}
	}()

	go func() {
		for {
			data, rerr := jitter.ReadData()
			if rerr != nil {
				errCh <- rerr
				return
			}
			if werr := writeAll(req.Conn, data); werr != nil {
				errCh <- werr
				return
			}
		}
	}()

	err = <-errCh
	if !isExpectedClose(err) {
		log.Printf("client: stream ended: %v", err)
	}
}

func writeAll(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func isExpectedClose(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)
}

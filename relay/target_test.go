package relay

import (
	"errors"
	"net"
	"testing"
)

func TestValidateConnectTargetAllowsPublicTargets(t *testing.T) {
	t.Parallel()

	got, err := validateConnectTarget("example.com:443", false)
	if err != nil {
		t.Fatalf("validateConnectTarget() error = %v, want nil", err)
	}
	if got != "example.com:443" {
		t.Fatalf("validateConnectTarget() = %q, want %q", got, "example.com:443")
	}
}

func TestValidateConnectTargetDeniesLocalTargetsByDefault(t *testing.T) {
	t.Parallel()

	for _, target := range []string{
		"localhost:80",
		"127.0.0.1:22",
		"[::1]:22",
		"169.254.10.20:8080",
	} {
		_, err := validateConnectTarget(target, false)
		if !errors.Is(err, errLocalTargetDenied) {
			t.Fatalf("target %q: error = %v, want errLocalTargetDenied", target, err)
		}
	}
}

func TestValidateConnectTargetAllowsLocalWhenEnabled(t *testing.T) {
	t.Parallel()

	for _, target := range []string{
		"localhost:80",
		"127.0.0.1:22",
		"[::1]:22",
	} {
		if _, err := validateConnectTarget(target, true); err != nil {
			t.Fatalf("target %q: error = %v, want nil", target, err)
		}
	}
}

func TestValidateConnectTargetRejectsInvalidPort(t *testing.T) {
	t.Parallel()

	if _, err := validateConnectTarget("example.com:70000", false); err == nil {
		t.Fatal("validateConnectTarget() expected error for invalid port, got nil")
	}
}

func TestFirstAllowedIPSkipsDeniedTargets(t *testing.T) {
	t.Parallel()

	ips := []net.IP{
		net.ParseIP("127.0.0.1"),
		net.ParseIP("::1"),
		net.ParseIP("93.184.216.34"),
	}
	got, ok := firstAllowedIP(ips)
	if !ok {
		t.Fatal("firstAllowedIP() = no result, want a public IP")
	}
	if got.String() != "93.184.216.34" {
		t.Fatalf("firstAllowedIP() = %s, want %s", got, "93.184.216.34")
	}
}

func TestFirstAllowedIPReturnsFalseWhenAllDenied(t *testing.T) {
	t.Parallel()

	ips := []net.IP{
		net.ParseIP("127.0.0.1"),
		net.ParseIP("::1"),
		net.ParseIP("169.254.1.20"),
	}
	if _, ok := firstAllowedIP(ips); ok {
		t.Fatal("firstAllowedIP() unexpectedly returned an allowed IP")
	}
}

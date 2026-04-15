package relay

import (
	"errors"
	"testing"

	"codeberg.org/urutau-ltd/bellbird/proxy"
)

func TestValidateAuthFrameAcceptsMatchingToken(t *testing.T) {
	t.Parallel()

	if err := validateAuthFrame("s3cr3t", proxy.PacketAuth, []byte("s3cr3t")); err != nil {
		t.Fatalf("validateAuthFrame() error = %v, want nil", err)
	}
}

func TestValidateAuthFrameRejectsMissingAuthFrame(t *testing.T) {
	t.Parallel()

	err := validateAuthFrame("s3cr3t", proxy.PacketConnect, []byte("example.com:443"))
	if !errors.Is(err, errAuthFrameRequired) {
		t.Fatalf("validateAuthFrame() error = %v, want errAuthFrameRequired", err)
	}
}

func TestValidateAuthFrameRejectsBadToken(t *testing.T) {
	t.Parallel()

	err := validateAuthFrame("s3cr3t", proxy.PacketAuth, []byte("wrong"))
	if !errors.Is(err, errAuthTokenInvalid) {
		t.Fatalf("validateAuthFrame() error = %v, want errAuthTokenInvalid", err)
	}
}

package proxy

import (
	"bytes"
	"testing"
)

func TestPadUnpadRoundTrip(t *testing.T) {
	t.Parallel()

	payload := []byte("hello world")
	padded := PadData(payload, PadSize(len(payload)))

	if len(padded)%DefaultBlockSize != 0 {
		t.Fatalf("padded len = %d, expected multiple of %d", len(padded), DefaultBlockSize)
	}

	got := UnpadData(padded)
	if !bytes.Equal(got, payload) {
		t.Fatalf("unpad mismatch: got %q want %q", got, payload)
	}
}

func TestPadDataExtendsSmallTarget(t *testing.T) {
	t.Parallel()

	payload := []byte{1, 2, 3, 4}
	padded := PadData(payload, 1)

	if len(padded) < len(payload)+2 {
		t.Fatalf("padded len = %d, want at least %d", len(padded), len(payload)+2)
	}

	got := UnpadData(padded)
	if !bytes.Equal(got, payload) {
		t.Fatalf("unpad mismatch: got %v want %v", got, payload)
	}
}

func TestPadSizeAlwaysCoversLengthPrefix(t *testing.T) {
	t.Parallel()

	for _, n := range []int{0, 1, 509, 510, 511, 512, 1024} {
		size := PadSize(n)
		if size < n+2 {
			t.Fatalf("PadSize(%d)=%d, want >= %d", n, size, n+2)
		}
		if size%DefaultBlockSize != 0 {
			t.Fatalf("PadSize(%d)=%d, not a multiple of %d", n, size, DefaultBlockSize)
		}
	}
}

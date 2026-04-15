package proxy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyLoadAndEval(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "policy.zy")
	src := `
(defn packet_delay_ms [] 11.5)
(defn inject_dummy [] true)
(defn pad_to_size [n] (+ n 64))
`
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	p, err := NewPolicy(path)
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}

	if got := p.DelayMs(); got != 11.5 {
		t.Fatalf("DelayMs() = %v, want 11.5", got)
	}
	if got := p.InjectDummy(); !got {
		t.Fatal("InjectDummy() = false, want true")
	}
	if got := p.PadToSize(100); got != 164 {
		t.Fatalf("PadToSize(100) = %d, want 164", got)
	}
}

func TestPolicyReload(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "policy.zy")

	initial := `
(defn packet_delay_ms [] 5)
(defn inject_dummy [] false)
(defn pad_to_size [n] (+ n 8))
`
	if err := os.WriteFile(path, []byte(initial), 0o600); err != nil {
		t.Fatalf("write initial policy file: %v", err)
	}

	p, err := NewPolicy(path)
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	if got := p.DelayMs(); got != 5 {
		t.Fatalf("DelayMs() = %v, want 5", got)
	}

	updated := `
(defn packet_delay_ms [] 20)
(defn inject_dummy [] true)
(defn pad_to_size [n] (+ n 32))
`
	if err := os.WriteFile(path, []byte(updated), 0o600); err != nil {
		t.Fatalf("write updated policy file: %v", err)
	}

	if err := p.Reload(); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}

	if got := p.DelayMs(); got != 20 {
		t.Fatalf("DelayMs() = %v, want 20", got)
	}
	if got := p.InjectDummy(); !got {
		t.Fatal("InjectDummy() = false, want true")
	}
	if got := p.PadToSize(10); got != 42 {
		t.Fatalf("PadToSize(10) = %d, want 42", got)
	}
}

package proxy

import (
	"fmt"
	"math"
	"math/rand"
	"os"
	"sync"

	"github.com/glycerine/zygomys/zygo"
)

// Policy loads and evaluates a zygomys (.zy) policy script.
// It exposes exactly three functions that the jitter engine calls:
//
//	(packet_delay_ms)    → float  — ms to wait before sending a frame
//	(inject_dummy)       → bool   — whether to inject a dummy packet now
//	(pad_to_size n)      → float  — target padded byte count for payload of n bytes
//
// The script is re-evaluated on every call, so hot-reload via Reload()
// takes effect immediately on the next packet.
type Policy struct {
	mu     sync.RWMutex
	env    *zygo.Zlisp
	path   string
	source string // cached for reload
}

// zygomys sandbox initialization touches shared global parser state.
// Serialize environment creation/validation to avoid cross-instance races.
var zygoSandboxMu sync.Mutex

// NewPolicy loads a policy from path and validates it by calling all three
// required functions once. Returns an error if any function is missing.
func NewPolicy(path string) (*Policy, error) {
	p := &Policy{path: path}
	if err := p.load(); err != nil {
		return nil, err
	}
	return p, nil
}

// Reload re-reads the policy file and hot-swaps the environment.
// Safe to call from a signal handler or goroutine.
// Inflight calls to DelayMs/InjectDummy/PadToSize complete with the old policy.
func (p *Policy) Reload() error {
	return p.load()
}

// DelayMs returns the jitter delay in milliseconds for the next outgoing packet.
// Falls back to 10ms on evaluation error.
func (p *Policy) DelayMs() float64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	v, err := p.env.EvalString("(packet_delay_ms)")
	if err != nil {
		return 10.0
	}
	return sexpToFloat(v)
}

// InjectDummy returns true if a dummy packet should be injected right now.
// Falls back to false on evaluation error.
func (p *Policy) InjectDummy() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	v, err := p.env.EvalString("(inject_dummy)")
	if err != nil {
		return false
	}
	return sexpToBool(v)
}

// PadToSize returns the target padded size in bytes for a payload of n bytes.
// Falls back to PadSize(n) on evaluation error.
func (p *Policy) PadToSize(n int) int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	v, err := p.env.EvalString(fmt.Sprintf("(pad_to_size %d)", n))
	if err != nil {
		return PadSize(n)
	}
	return int(sexpToFloat(v))
}

func (p *Policy) load() error {
	data, err := os.ReadFile(p.path)
	if err != nil {
		return fmt.Errorf("policy: read %s: %w", p.path, err)
	}
	src := string(data)

	zygoSandboxMu.Lock()
	defer zygoSandboxMu.Unlock()

	env := zygo.NewZlispSandbox()
	registerBuiltins(env)

	if err := env.LoadString(src); err != nil {
		return fmt.Errorf("policy: parse %s: %w", p.path, err)
	}

	// Validate that required functions exist
	for _, call := range []string{"(packet_delay_ms)", "(inject_dummy)", "(pad_to_size 64)"} {
		if _, err := env.EvalString(call); err != nil {
			return fmt.Errorf("policy: required function missing — failed %q: %w", call, err)
		}
	}

	p.mu.Lock()
	p.env = env
	p.source = src
	p.mu.Unlock()
	return nil
}

// registerBuiltins adds math helpers that policy scripts can use.
// These are not in the default zygomys environment.
func registerBuiltins(env *zygo.Zlisp) {
	// (rand) → uniform float in [0, 1)
	env.AddFunction("rand", func(_ *zygo.Zlisp, _ string, _ []zygo.Sexp) (zygo.Sexp, error) {
		return &zygo.SexpFloat{Val: rand.Float64()}, nil
	})

	// (rand-exp lambda) → exponential variate with given rate λ
	// Mean = 1/λ. Use λ < 1 for larger mean delays.
	env.AddFunction("rand-exp", func(_ *zygo.Zlisp, _ string, args []zygo.Sexp) (zygo.Sexp, error) {
		lambda := 0.3
		if len(args) > 0 {
			lambda = sexpToFloat(args[0])
		}
		if lambda <= 0 {
			lambda = 0.3
		}
		return &zygo.SexpFloat{Val: rand.ExpFloat64() / lambda}, nil
	})

	// (ceil x) → smallest integer >= x
	env.AddFunction("ceil", func(_ *zygo.Zlisp, _ string, args []zygo.Sexp) (zygo.Sexp, error) {
		if len(args) == 0 {
			return &zygo.SexpFloat{Val: 0}, nil
		}
		return &zygo.SexpFloat{Val: math.Ceil(sexpToFloat(args[0]))}, nil
	})

	// (floor x) → largest integer <= x
	env.AddFunction("floor", func(_ *zygo.Zlisp, _ string, args []zygo.Sexp) (zygo.Sexp, error) {
		if len(args) == 0 {
			return &zygo.SexpFloat{Val: 0}, nil
		}
		return &zygo.SexpFloat{Val: math.Floor(sexpToFloat(args[0]))}, nil
	})
}

func sexpToFloat(v zygo.Sexp) float64 {
	switch x := v.(type) {
	case *zygo.SexpFloat:
		return x.Val
	case *zygo.SexpInt:
		return float64(x.Val)
	}
	return 0
}

func sexpToBool(v zygo.Sexp) bool {
	if b, ok := v.(*zygo.SexpBool); ok {
		return b.Val
	}
	return false
}

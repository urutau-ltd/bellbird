package proxy

import (
	"context"
	crand "crypto/rand"
	"math/rand"
	"time"
)

// Jitter wraps a Tunnel and applies three traffic-analysis defenses
// inspired by Mullvad's DAITA (Defense Against AI-guided Traffic Analysis):
//
//  1. Timing jitter   — random delay before each outgoing frame
//  2. Dummy injection — probabilistic fake frames at random intervals
//  3. Size normalization — all frames padded to multiples of DefaultBlockSize
//
// Only outgoing traffic from the client is shaped. Relay→client responses
// are padded by the relay using PadSize() before framing.
type Jitter struct {
	tunnel *Tunnel
	policy *Policy
}

// NewJitter wraps t with traffic-shaping controlled by p.
func NewJitter(t *Tunnel, p *Policy) *Jitter {
	return &Jitter{tunnel: t, policy: p}
}

// SendData pads, delays, then sends payload as a PacketData frame.
//
// Steps:
//  1. Determine target padded size from policy: (pad_to_size n)
//  2. Encode as [orig_len:2][data][padding] via PadData
//  3. Sleep for (packet_delay_ms) milliseconds
//  4. Write encrypted frame to tunnel
func (j *Jitter) SendData(payload []byte) error {
	targetSize := j.policy.PadToSize(len(payload))
	padded := PadData(payload, targetSize)

	delayMs := j.policy.DelayMs()
	if delayMs > 0 {
		time.Sleep(time.Duration(delayMs * float64(time.Millisecond)))
	}

	return j.tunnel.WriteFrame(PacketData, padded)
}

// ReadData reads the next PacketData frame, discarding dummy and ping frames.
// Blocks until a data frame arrives or the connection closes.
func (j *Jitter) ReadData() ([]byte, error) {
	for {
		pktType, payload, err := j.tunnel.ReadFrame()
		if err != nil {
			return nil, err
		}
		switch pktType {
		case PacketData:
			return UnpadData(payload), nil
		case PacketDummy, PacketPing:
			// Silently discard — these exist only to confuse observers.
		}
	}
}

// RunDummyInjector starts a background goroutine that injects PacketDummy
// frames at random intervals. Stops when ctx is cancelled.
//
// The goroutine checks the policy predicate (inject_dummy) each tick.
// This means hot-reloaded policies take effect on the next tick.
//
// Dummy frames are padded to a random size (1–256 bytes → padded to block boundary)
// so they resemble real data frames in size.
func (j *Jitter) RunDummyInjector(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(randomDummyInterval()):
				if j.policy.InjectDummy() {
					rawSize := rand.Intn(256) + 1
					targetSize := PadSize(rawSize)
					dummy := make([]byte, targetSize)
					if _, err := crand.Read(dummy); err != nil {
						_, _ = rand.Read(dummy)
					}
					// Ignore send errors: the main data pipe will catch the broken conn.
					_ = j.tunnel.WriteFrame(PacketDummy, dummy)
				}
			}
		}
	}()
}

// randomDummyInterval returns a uniform random interval in [50ms, 200ms].
// This range is deliberate: too short wastes bandwidth, too long makes
// the injector useless against burst-timing analysis.
func randomDummyInterval() time.Duration {
	return time.Duration(50+rand.Intn(150)) * time.Millisecond
}

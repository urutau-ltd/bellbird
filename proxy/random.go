package proxy

import (
	crand "crypto/rand"
	"encoding/binary"
	"math/rand"
	"time"
)

func init() {
	var seedBytes [8]byte
	if _, err := crand.Read(seedBytes[:]); err == nil {
		rand.Seed(int64(binary.LittleEndian.Uint64(seedBytes[:])))
		return
	}
	rand.Seed(time.Now().UnixNano())
}

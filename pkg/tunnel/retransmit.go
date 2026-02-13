package tunnel

import (
	"sync"
)

// retransmitBuf stores sent frames keyed by sequence number for retransmission
// after reconnection. It enforces a maximum byte capacity — when full, new
// writes fail with ErrBufFull (the session is unrecoverable).
type retransmitBuf struct {
	mu      sync.Mutex
	entries []bufEntry
	size    int // current total bytes of stored frames
	maxSize int // capacity in bytes
}

type bufEntry struct {
	seq   uint64
	frame []byte // full wire frame (header + payload)
}

func newRetransmitBuf(maxSize int) *retransmitBuf {
	return &retransmitBuf{
		maxSize: maxSize,
	}
}

// add stores a frame for potential retransmission. Returns ErrBufFull if
// adding this frame would exceed the buffer capacity.
func (b *retransmitBuf) add(seq uint64, frame []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.size+len(frame) > b.maxSize {
		return ErrBufFull
	}

	// Make a copy so the caller can reuse the slice.
	f := make([]byte, len(frame))
	copy(f, frame)

	b.entries = append(b.entries, bufEntry{seq: seq, frame: f})
	b.size += len(f)
	return nil
}

// freeTo removes all entries with seq <= ackSeq (they've been acknowledged
// by the peer and will never need retransmission).
func (b *retransmitBuf) freeTo(ackSeq uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	i := 0
	for i < len(b.entries) && b.entries[i].seq <= ackSeq {
		b.size -= len(b.entries[i].frame)
		i++
	}
	if i > 0 {
		b.entries = b.entries[i:]
	}
}

// framesFrom returns copies of all stored frames with seq >= fromSeq,
// in sequence order. Used during reconnection to retransmit unACK'd data.
func (b *retransmitBuf) framesFrom(fromSeq uint64) [][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()

	var result [][]byte
	for _, e := range b.entries {
		if e.seq >= fromSeq {
			result = append(result, e.frame)
		}
	}
	return result
}


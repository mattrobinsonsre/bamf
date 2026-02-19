package webterm

import "sync"

// DefaultRingBufSize is the default ring buffer size (64KB).
const DefaultRingBufSize = 64 * 1024

// RingBuffer is a fixed-size circular buffer that overwrites oldest data
// when full. Used to buffer agent→client output during detached state
// (API pod restart, brief network blip).
type RingBuffer struct {
	mu   sync.Mutex
	buf  []byte
	size int
	pos  int  // next write position
	full bool // true once the buffer has wrapped at least once
}

// NewRingBuffer creates a ring buffer with the given capacity.
func NewRingBuffer(size int) *RingBuffer {
	return &RingBuffer{
		buf:  make([]byte, size),
		size: size,
	}
}

// Write appends data to the buffer, overwriting oldest bytes if full.
func (rb *RingBuffer) Write(p []byte) (int, error) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	n := len(p)
	if n == 0 {
		return 0, nil
	}

	// If data is larger than buffer, only keep the tail.
	if n >= rb.size {
		copy(rb.buf, p[n-rb.size:])
		rb.pos = 0
		rb.full = true
		return n, nil
	}

	// Copy data, handling wrap-around.
	remaining := rb.size - rb.pos
	if n <= remaining {
		copy(rb.buf[rb.pos:], p)
	} else {
		copy(rb.buf[rb.pos:], p[:remaining])
		copy(rb.buf, p[remaining:])
	}

	newPos := rb.pos + n
	if newPos >= rb.size {
		rb.full = true
		newPos -= rb.size
	}
	rb.pos = newPos

	return n, nil
}

// ReadAll returns all buffered data in order and resets the buffer.
func (rb *RingBuffer) ReadAll() []byte {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if !rb.full && rb.pos == 0 {
		return nil
	}

	var result []byte
	if rb.full {
		// Data wraps: [pos..size) + [0..pos)
		result = make([]byte, rb.size)
		copy(result, rb.buf[rb.pos:])
		copy(result[rb.size-rb.pos:], rb.buf[:rb.pos])
	} else {
		// No wrap: [0..pos)
		result = make([]byte, rb.pos)
		copy(result, rb.buf[:rb.pos])
	}

	// Reset
	rb.pos = 0
	rb.full = false

	return result
}

// Len returns the number of bytes currently in the buffer.
func (rb *RingBuffer) Len() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	if rb.full {
		return rb.size
	}
	return rb.pos
}

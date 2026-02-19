// Package webterm implements browser-based terminal sessions for the bridge.
//
// The bridge holds all session state (SSH connections, PTY subprocesses).
// The API is a pure stateless relay between the browser WebSocket and the
// bridge frame protocol.
//
// Frame protocol (API ↔ Bridge):
//
//	[1-byte type][2-byte payload length (big-endian)][payload]
//
//	Type 0x01: Terminal data (payload = raw bytes)
//	Type 0x02: Resize (payload = 2-byte cols + 2-byte rows, big-endian)
//	Type 0x03: Status (payload = UTF-8 string: "ready", "error:msg", "detached", "resumed")
package webterm

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

// Frame types for the API ↔ Bridge protocol.
const (
	FrameData   byte = 0x01
	FrameResize byte = 0x02
	FrameStatus byte = 0x03
)

// MaxFramePayload is the maximum allowed payload size (64KB).
const MaxFramePayload = 65535

// FrameWriter writes framed messages to a writer.
type FrameWriter struct {
	w  io.Writer
	mu sync.Mutex
}

// NewFrameWriter creates a FrameWriter wrapping the given writer.
func NewFrameWriter(w io.Writer) *FrameWriter {
	return &FrameWriter{w: w}
}

// WriteData writes a terminal data frame (type 0x01).
func (fw *FrameWriter) WriteData(p []byte) error {
	return fw.writeFrame(FrameData, p)
}

// WriteResize writes a terminal resize frame (type 0x02).
func (fw *FrameWriter) WriteResize(cols, rows uint16) error {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint16(payload[0:2], cols)
	binary.BigEndian.PutUint16(payload[2:4], rows)
	return fw.writeFrame(FrameResize, payload)
}

// WriteStatus writes a status frame (type 0x03).
func (fw *FrameWriter) WriteStatus(msg string) error {
	return fw.writeFrame(FrameStatus, []byte(msg))
}

// writeFrame writes a single frame atomically.
func (fw *FrameWriter) writeFrame(typ byte, payload []byte) error {
	if len(payload) > MaxFramePayload {
		return fmt.Errorf("payload too large: %d > %d", len(payload), MaxFramePayload)
	}

	fw.mu.Lock()
	defer fw.mu.Unlock()

	header := [3]byte{typ, 0, 0}
	binary.BigEndian.PutUint16(header[1:3], uint16(len(payload)))

	if _, err := fw.w.Write(header[:]); err != nil {
		return fmt.Errorf("write frame header: %w", err)
	}
	if len(payload) > 0 {
		if _, err := fw.w.Write(payload); err != nil {
			return fmt.Errorf("write frame payload: %w", err)
		}
	}
	return nil
}

// FrameReader reads framed messages from a reader.
type FrameReader struct {
	r io.Reader
}

// NewFrameReader creates a FrameReader wrapping the given reader.
func NewFrameReader(r io.Reader) *FrameReader {
	return &FrameReader{r: r}
}

// ReadFrame reads a single frame, returning type and payload.
func (fr *FrameReader) ReadFrame() (typ byte, payload []byte, err error) {
	var header [3]byte
	if _, err := io.ReadFull(fr.r, header[:]); err != nil {
		return 0, nil, err
	}

	typ = header[0]
	length := binary.BigEndian.Uint16(header[1:3])

	if length == 0 {
		return typ, nil, nil
	}

	payload = make([]byte, length)
	if _, err := io.ReadFull(fr.r, payload); err != nil {
		return 0, nil, fmt.Errorf("read frame payload: %w", err)
	}

	return typ, payload, nil
}

// ParseResize extracts cols and rows from a resize frame payload.
func ParseResize(payload []byte) (cols, rows uint16, err error) {
	if len(payload) != 4 {
		return 0, 0, fmt.Errorf("invalid resize payload length: %d", len(payload))
	}
	cols = binary.BigEndian.Uint16(payload[0:2])
	rows = binary.BigEndian.Uint16(payload[2:4])
	return cols, rows, nil
}

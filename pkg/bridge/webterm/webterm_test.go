package webterm

import (
	"bytes"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Frame protocol tests
// ---------------------------------------------------------------------------

func TestFrameWriteReadRoundtrip(t *testing.T) {
	tests := []struct {
		name    string
		typ     byte
		payload []byte
	}{
		{
			name:    "data frame with content",
			typ:     FrameData,
			payload: []byte("hello terminal"),
		},
		{
			name:    "data frame empty payload",
			typ:     FrameData,
			payload: nil,
		},
		{
			name:    "status frame ready",
			typ:     FrameStatus,
			payload: []byte("ready"),
		},
		{
			name:    "status frame error",
			typ:     FrameStatus,
			payload: []byte("error:connection refused"),
		},
		{
			name:    "status frame detached",
			typ:     FrameStatus,
			payload: []byte("detached"),
		},
		{
			name:    "status frame resumed",
			typ:     FrameStatus,
			payload: []byte("resumed"),
		},
		{
			name: "resize frame",
			typ:  FrameResize,
			payload: func() []byte {
				p := make([]byte, 4)
				binary.BigEndian.PutUint16(p[0:2], 120)
				binary.BigEndian.PutUint16(p[2:4], 40)
				return p
			}(),
		},
		{
			name:    "single byte payload",
			typ:     FrameData,
			payload: []byte{0x42},
		},
		{
			name:    "binary payload with null bytes",
			typ:     FrameData,
			payload: []byte{0x00, 0x01, 0x00, 0xff},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			fw := NewFrameWriter(&buf)

			err := fw.writeFrame(tt.typ, tt.payload)
			require.NoError(t, err)

			fr := NewFrameReader(&buf)
			gotTyp, gotPayload, err := fr.ReadFrame()
			require.NoError(t, err)
			require.Equal(t, tt.typ, gotTyp)

			if tt.payload == nil {
				require.Nil(t, gotPayload)
			} else {
				require.Equal(t, tt.payload, gotPayload)
			}
		})
	}
}

func TestFrameWriteData(t *testing.T) {
	var buf bytes.Buffer
	fw := NewFrameWriter(&buf)

	data := []byte("some terminal output")
	err := fw.WriteData(data)
	require.NoError(t, err)

	fr := NewFrameReader(&buf)
	typ, payload, err := fr.ReadFrame()
	require.NoError(t, err)
	require.Equal(t, FrameData, typ)
	require.Equal(t, data, payload)
}

func TestFrameWriteResize(t *testing.T) {
	var buf bytes.Buffer
	fw := NewFrameWriter(&buf)

	err := fw.WriteResize(132, 43)
	require.NoError(t, err)

	fr := NewFrameReader(&buf)
	typ, payload, err := fr.ReadFrame()
	require.NoError(t, err)
	require.Equal(t, FrameResize, typ)

	cols, rows, err := ParseResize(payload)
	require.NoError(t, err)
	require.Equal(t, uint16(132), cols)
	require.Equal(t, uint16(43), rows)
}

func TestFrameWriteStatus(t *testing.T) {
	var buf bytes.Buffer
	fw := NewFrameWriter(&buf)

	err := fw.WriteStatus("ready")
	require.NoError(t, err)

	fr := NewFrameReader(&buf)
	typ, payload, err := fr.ReadFrame()
	require.NoError(t, err)
	require.Equal(t, FrameStatus, typ)
	require.Equal(t, "ready", string(payload))
}

func TestFrameMultipleFrames(t *testing.T) {
	var buf bytes.Buffer
	fw := NewFrameWriter(&buf)

	require.NoError(t, fw.WriteStatus("ready"))
	require.NoError(t, fw.WriteData([]byte("line 1\n")))
	require.NoError(t, fw.WriteResize(80, 24))
	require.NoError(t, fw.WriteData([]byte("line 2\n")))

	fr := NewFrameReader(&buf)

	typ, payload, err := fr.ReadFrame()
	require.NoError(t, err)
	require.Equal(t, FrameStatus, typ)
	require.Equal(t, "ready", string(payload))

	typ, payload, err = fr.ReadFrame()
	require.NoError(t, err)
	require.Equal(t, FrameData, typ)
	require.Equal(t, "line 1\n", string(payload))

	typ, payload, err = fr.ReadFrame()
	require.NoError(t, err)
	require.Equal(t, FrameResize, typ)
	cols, rows, err := ParseResize(payload)
	require.NoError(t, err)
	require.Equal(t, uint16(80), cols)
	require.Equal(t, uint16(24), rows)

	typ, payload, err = fr.ReadFrame()
	require.NoError(t, err)
	require.Equal(t, FrameData, typ)
	require.Equal(t, "line 2\n", string(payload))
}

func TestFrameMaxSizePayload(t *testing.T) {
	var buf bytes.Buffer
	fw := NewFrameWriter(&buf)

	// MaxFramePayload = 65535 — exactly at the limit should succeed.
	bigPayload := make([]byte, MaxFramePayload)
	for i := range bigPayload {
		bigPayload[i] = byte(i % 256)
	}

	err := fw.WriteData(bigPayload)
	require.NoError(t, err)

	fr := NewFrameReader(&buf)
	typ, payload, err := fr.ReadFrame()
	require.NoError(t, err)
	require.Equal(t, FrameData, typ)
	require.Equal(t, bigPayload, payload)
}

func TestFramePayloadTooLarge(t *testing.T) {
	var buf bytes.Buffer
	fw := NewFrameWriter(&buf)

	oversized := make([]byte, MaxFramePayload+1)
	err := fw.writeFrame(FrameData, oversized)
	require.Error(t, err)
	require.Contains(t, err.Error(), "payload too large")
}

func TestFrameReadEOF(t *testing.T) {
	// Reading from an empty reader should return EOF.
	fr := NewFrameReader(bytes.NewReader(nil))
	_, _, err := fr.ReadFrame()
	require.ErrorIs(t, err, io.EOF)
}

func TestFrameReadTruncatedHeader(t *testing.T) {
	// Only 2 bytes — header needs 3.
	fr := NewFrameReader(bytes.NewReader([]byte{0x01, 0x00}))
	_, _, err := fr.ReadFrame()
	require.Error(t, err)
}

func TestFrameReadTruncatedPayload(t *testing.T) {
	// Header claims 10 bytes of payload, but only 3 provided.
	header := []byte{FrameData, 0x00, 0x0a} // length = 10
	data := append(header, []byte("abc")...)
	fr := NewFrameReader(bytes.NewReader(data))
	_, _, err := fr.ReadFrame()
	require.Error(t, err)
	require.Contains(t, err.Error(), "read frame payload")
}

// ---------------------------------------------------------------------------
// ParseResize tests
// ---------------------------------------------------------------------------

func TestParseResize(t *testing.T) {
	tests := []struct {
		name    string
		cols    uint16
		rows    uint16
		wantErr bool
	}{
		{name: "standard 80x24", cols: 80, rows: 24},
		{name: "large 300x100", cols: 300, rows: 100},
		{name: "minimum 1x1", cols: 1, rows: 1},
		{name: "zero values", cols: 0, rows: 0},
		{name: "max uint16", cols: 65535, rows: 65535},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := make([]byte, 4)
			binary.BigEndian.PutUint16(payload[0:2], tt.cols)
			binary.BigEndian.PutUint16(payload[2:4], tt.rows)

			cols, rows, err := ParseResize(payload)
			require.NoError(t, err)
			require.Equal(t, tt.cols, cols)
			require.Equal(t, tt.rows, rows)
		})
	}
}

func TestParseResizeInvalidPayload(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{name: "empty", payload: nil},
		{name: "too short 1 byte", payload: []byte{0x00}},
		{name: "too short 3 bytes", payload: []byte{0x00, 0x50, 0x00}},
		{name: "too long 5 bytes", payload: []byte{0x00, 0x50, 0x00, 0x18, 0xff}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ParseResize(tt.payload)
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid resize payload length")
		})
	}
}

// ---------------------------------------------------------------------------
// Ring buffer tests
// ---------------------------------------------------------------------------

func TestRingBufferWriteAndReadAll(t *testing.T) {
	rb := NewRingBuffer(64)

	n, err := rb.Write([]byte("hello"))
	require.NoError(t, err)
	require.Equal(t, 5, n)

	data := rb.ReadAll()
	require.Equal(t, []byte("hello"), data)
}

func TestRingBufferReadAllEmpty(t *testing.T) {
	rb := NewRingBuffer(64)
	data := rb.ReadAll()
	require.Nil(t, data)
}

func TestRingBufferReadAllResetsBuffer(t *testing.T) {
	rb := NewRingBuffer(64)

	_, _ = rb.Write([]byte("first"))
	data := rb.ReadAll()
	require.Equal(t, []byte("first"), data)

	// Second ReadAll should be empty.
	data = rb.ReadAll()
	require.Nil(t, data)
}

func TestRingBufferMultipleWrites(t *testing.T) {
	rb := NewRingBuffer(64)

	_, _ = rb.Write([]byte("aaa"))
	_, _ = rb.Write([]byte("bbb"))
	_, _ = rb.Write([]byte("ccc"))

	data := rb.ReadAll()
	require.Equal(t, []byte("aaabbbccc"), data)
}

func TestRingBufferWriteAfterReadAll(t *testing.T) {
	rb := NewRingBuffer(64)

	_, _ = rb.Write([]byte("before"))
	rb.ReadAll()

	_, _ = rb.Write([]byte("after"))
	data := rb.ReadAll()
	require.Equal(t, []byte("after"), data)
}

func TestRingBufferOverflowOverwritesOldest(t *testing.T) {
	// Buffer of size 8 — writing 10 bytes should keep only the last 8.
	rb := NewRingBuffer(8)

	n, err := rb.Write([]byte("abcdefghij")) // 10 bytes
	require.NoError(t, err)
	require.Equal(t, 10, n)

	data := rb.ReadAll()
	// Should keep the tail: "cdefghij" (last 8 of 10).
	require.Equal(t, []byte("cdefghij"), data)
}

func TestRingBufferOverflowMultipleSmallWrites(t *testing.T) {
	rb := NewRingBuffer(8)

	// Write 5 bytes, then 5 more — total 10, capacity 8.
	_, _ = rb.Write([]byte("12345"))
	_, _ = rb.Write([]byte("67890"))

	data := rb.ReadAll()
	// Buffer wraps: wrote [1,2,3,4,5] to pos 0..4, then [6,7,8,9,0] wraps.
	// After first write: pos=5, full=false, buf=[1,2,3,4,5,0,0,0]
	// After second write: 8-5=3 remaining, write [6,7,8] at pos 5..7, then
	//   [9,0] at pos 0..1, pos=2, full=true
	//   buf=[9,0,3,4,5,6,7,8]
	// ReadAll when full: buf[pos..] + buf[..pos] = buf[2..8] + buf[0..2]
	//   = [3,4,5,6,7,8] + [9,0] = "34567890"
	require.Equal(t, []byte("34567890"), data)
}

func TestRingBufferExactCapacity(t *testing.T) {
	rb := NewRingBuffer(5)

	_, _ = rb.Write([]byte("exact"))
	require.Equal(t, 5, rb.Len())

	data := rb.ReadAll()
	require.Equal(t, []byte("exact"), data)
}

func TestRingBufferWriteExactlyDoubleCapacity(t *testing.T) {
	rb := NewRingBuffer(4)

	// Writing exactly 2x capacity — only last 4 bytes kept.
	_, _ = rb.Write([]byte("abcdefgh")) // 8 bytes, cap 4
	data := rb.ReadAll()
	require.Equal(t, []byte("efgh"), data)
}

func TestRingBufferWriteEmptySlice(t *testing.T) {
	rb := NewRingBuffer(8)

	n, err := rb.Write([]byte{})
	require.NoError(t, err)
	require.Equal(t, 0, n)
	require.Equal(t, 0, rb.Len())

	data := rb.ReadAll()
	require.Nil(t, data)
}

func TestRingBufferLen(t *testing.T) {
	rb := NewRingBuffer(16)

	require.Equal(t, 0, rb.Len())

	_, _ = rb.Write([]byte("hello"))
	require.Equal(t, 5, rb.Len())

	_, _ = rb.Write([]byte(" world"))
	require.Equal(t, 11, rb.Len())

	// Overflow: 16 bytes of capacity, write 20 total.
	_, _ = rb.Write([]byte("!!!!!!!!!!")) // 10 more, total 21 > 16
	require.Equal(t, 16, rb.Len()) // Full — reports capacity.
}

func TestRingBufferLenAfterReadAll(t *testing.T) {
	rb := NewRingBuffer(16)

	_, _ = rb.Write([]byte("data"))
	require.Equal(t, 4, rb.Len())

	rb.ReadAll()
	require.Equal(t, 0, rb.Len())
}

func TestRingBufferWrapAroundThenReadAll(t *testing.T) {
	// A specific scenario: partially fill, read, write more across the wrap.
	rb := NewRingBuffer(8)

	// Fill 6 of 8 bytes.
	_, _ = rb.Write([]byte("123456"))
	require.Equal(t, 6, rb.Len())

	// Read and reset.
	data := rb.ReadAll()
	require.Equal(t, []byte("123456"), data)
	require.Equal(t, 0, rb.Len())

	// Now write 10 bytes — larger than capacity.
	_, _ = rb.Write([]byte("abcdefghij"))
	data = rb.ReadAll()
	require.Equal(t, []byte("cdefghij"), data)
}

// ---------------------------------------------------------------------------
// Session basic tests (no PTY/process spawning)
// ---------------------------------------------------------------------------

// mockReadWriteCloser is a simple in-memory ReadWriteCloser for testing.
type mockReadWriteCloser struct {
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
	closed   bool
}

func newMockRWC() *mockReadWriteCloser {
	return &mockReadWriteCloser{
		readBuf:  new(bytes.Buffer),
		writeBuf: new(bytes.Buffer),
	}
}

func (m *mockReadWriteCloser) Read(p []byte) (int, error) {
	if m.closed {
		return 0, io.EOF
	}
	return m.readBuf.Read(p)
}

func (m *mockReadWriteCloser) Write(p []byte) (int, error) {
	if m.closed {
		return 0, io.ErrClosedPipe
	}
	return m.writeBuf.Write(p)
}

func (m *mockReadWriteCloser) Close() error {
	m.closed = true
	return nil
}

func pipePair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

func TestSessionNewIsNotDetached(t *testing.T) {
	clientConn, _ := pipePair(t)
	agentIO := newMockRWC()
	logger := slog.Default()

	s := NewSession("test-session-1", "web-ssh", clientConn, agentIO, logger)
	defer s.Close()

	require.False(t, s.IsDetached())
	require.Equal(t, "test-session-1", s.ID)
	require.Equal(t, "web-ssh", s.Protocol)
}

func TestSessionCloseIdempotent(t *testing.T) {
	clientConn, _ := pipePair(t)
	agentIO := newMockRWC()
	logger := slog.Default()

	s := NewSession("test-close", "web-ssh", clientConn, agentIO, logger)

	// Close twice — should not panic.
	s.Close()
	s.Close()

	require.True(t, agentIO.closed)
}

func TestSessionSendWarning(t *testing.T) {
	clientConn, _ := pipePair(t)
	agentIO := newMockRWC()
	logger := slog.Default()

	s := NewSession("test-warn", "web-ssh", clientConn, agentIO, logger)
	defer s.Close()

	s.SendWarning("drain in 30s")

	// Should be readable from WarnCh.
	msg := <-s.WarnCh
	require.Equal(t, "drain in 30s", msg)
}

func TestSessionSendWarningNonBlocking(t *testing.T) {
	clientConn, _ := pipePair(t)
	agentIO := newMockRWC()
	logger := slog.Default()

	s := NewSession("test-warn-nb", "web-ssh", clientConn, agentIO, logger)
	defer s.Close()

	// Fill the WarnCh buffer (capacity 8).
	for i := 0; i < 8; i++ {
		s.SendWarning("msg")
	}

	// 9th should not block — just dropped.
	s.SendWarning("overflow")
	require.Len(t, s.WarnCh, 8)
}

func TestSessionSetResizeFunc(t *testing.T) {
	clientConn, _ := pipePair(t)
	agentIO := newMockRWC()
	logger := slog.Default()

	s := NewSession("test-resize", "web-ssh", clientConn, agentIO, logger)
	defer s.Close()

	var gotCols, gotRows uint16
	s.SetResizeFunc(func(cols, rows uint16) {
		gotCols = cols
		gotRows = rows
	})

	// Verify the function is stored (invoked indirectly via runConnected,
	// but we can test the setter doesn't panic and stores the func).
	require.NotNil(t, s.resizeFn)
	s.resizeFn(120, 40)
	require.Equal(t, uint16(120), gotCols)
	require.Equal(t, uint16(40), gotRows)
}

func TestSessionReconnectDelivered(t *testing.T) {
	clientConn, _ := pipePair(t)
	agentIO := newMockRWC()
	logger := slog.Default()

	s := NewSession("test-reconn", "web-ssh", clientConn, agentIO, logger)
	defer s.Close()

	newConn, _ := pipePair(t)
	s.Reconnect(newConn)

	// Should be receivable from reconnectCh.
	got := <-s.reconnectCh
	require.Equal(t, newConn, got)
}

func TestSessionReconnectDropsWhenChannelFull(t *testing.T) {
	clientConn, _ := pipePair(t)
	agentIO := newMockRWC()
	logger := slog.Default()

	s := NewSession("test-reconn-full", "web-ssh", clientConn, agentIO, logger)
	defer s.Close()

	// Fill the buffered channel (capacity 1).
	first, _ := pipePair(t)
	s.Reconnect(first)

	// Second should not block — the connection is closed instead.
	second, _ := pipePair(t)
	s.Reconnect(second)

	// Only the first should be in the channel.
	got := <-s.reconnectCh
	require.Equal(t, first, got)
}

func TestSessionDetachedState(t *testing.T) {
	clientConn, _ := pipePair(t)
	agentIO := newMockRWC()
	logger := slog.Default()

	s := NewSession("test-detach", "web-ssh", clientConn, agentIO, logger)
	defer s.Close()

	require.False(t, s.IsDetached())

	// Manually set detached (normally done by runConnected/waitForReconnect).
	s.detached.Store(true)
	require.True(t, s.IsDetached())

	s.detached.Store(false)
	require.False(t, s.IsDetached())
}

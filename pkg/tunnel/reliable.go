// Package tunnel provides a reliable byte stream over a replaceable network
// connection. It is designed for BAMF's tunnel architecture where the bridge
// (middle relay) can die and be replaced without breaking the end-to-end
// application session (e.g., psql ↔ postgres).
//
// The reliable stream wraps a net.Conn with framing, sequence numbers, ACKs,
// and a retransmit buffer. When the underlying connection breaks, callers
// reconnect through a new bridge and call Reconnect() to resume the stream
// with no data loss.
//
// Frame wire format:
//
//	Data:      [0x01][8-byte seq (big-endian)][4-byte len (big-endian)][payload]
//	ACK:       [0x02][8-byte ack_seq (big-endian)]
//	Handshake: [0x03][8-byte next_expected_seq (big-endian)]
//
// The bridge never interprets these frames — it just relays bytes.
package tunnel

// Protocol spec: docs/architecture/tunnels.md

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Frame types on the wire.
const (
	frameData      byte = 0x01
	frameACK       byte = 0x02
	frameHandshake byte = 0x03
	frameClose     byte = 0x04
)

// Defaults.
const (
	DefaultBufSize   = 4 * 1024 * 1024 // 4 MB retransmit buffer
	maxFramePayload  = 64 * 1024       // 64 KB max payload per frame
	dataHeaderSize   = 1 + 8 + 4       // type + seq + len
	ackFrameSize     = 1 + 8           // type + ack_seq
	handshakeSize    = 1 + 8           // type + next_expected_seq
	ackInterval      = 50 * time.Millisecond
	reconnectTimeout = 30 * time.Second
)

// Sentinel errors returned by Read/Write when the underlying connection breaks.
var (
	ErrConnLost  = errors.New("reliable stream: connection lost")
	ErrBufFull   = errors.New("reliable stream: retransmit buffer full, session unrecoverable")
	ErrClosed    = errors.New("reliable stream: closed")
	ErrHandshake = errors.New("reliable stream: handshake failed")
)

// ReliableStream provides exactly-once, in-order delivery over a replaceable
// connection. Read and Write are safe to call from separate goroutines (one
// reader, one writer) — the same contract as net.Conn.
type ReliableStream struct {
	// Connection state — protected by connMu.
	connMu   sync.Mutex
	conn     net.Conn
	connLost bool
	closed   bool

	// Write path — writeMu serializes ALL writes to conn (data frames and
	// ACK frames). This prevents interleaved partial writes.
	writeMu sync.Mutex
	sendSeq uint64         // next sequence number to assign (only modified under writeMu)
	sendBuf *retransmitBuf // unACK'd frames

	// Read path — protected by readMu. Only one goroutine reads at a time.
	readMu   sync.Mutex
	readLeft []byte // remaining bytes from a partially-consumed frame payload

	// recvSeq is the next expected sequence number (high-water mark + 1).
	// Atomic so the ackLoop can read it without holding readMu.
	recvSeq atomic.Uint64

	// peerAck is the highest seq the peer has ACK'd. Atomic.
	peerAck atomic.Uint64

	// Background ACK sender.
	ackStop chan struct{}
	ackDone chan struct{}
}

// NewStream wraps conn in a reliable stream. bufSize sets the retransmit
// buffer capacity (0 = DefaultBufSize).
func NewStream(conn net.Conn, bufSize int) *ReliableStream {
	if bufSize <= 0 {
		bufSize = DefaultBufSize
	}
	s := &ReliableStream{
		conn:    conn,
		sendSeq: 1,
		sendBuf: newRetransmitBuf(bufSize),
		ackStop: make(chan struct{}),
		ackDone: make(chan struct{}),
	}
	s.recvSeq.Store(1)
	go s.ackLoop()
	return s
}

// Read reads the next chunk of application data from the stream. It blocks
// until data is available, the connection breaks (ErrConnLost), or the
// stream is closed (ErrClosed). Frames with seq < recvSeq (duplicates from
// retransmit) are silently discarded.
func (s *ReliableStream) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	// Drain any leftover bytes from a previous frame.
	if len(s.readLeft) > 0 {
		n := copy(p, s.readLeft)
		s.readLeft = s.readLeft[n:]
		return n, nil
	}

	for {
		if s.isClosed() {
			return 0, ErrClosed
		}
		if s.isConnLost() {
			return 0, ErrConnLost
		}

		conn := s.getConn()

		// Read frame header (1 byte type).
		var typeBuf [1]byte
		if _, err := io.ReadFull(conn, typeBuf[:]); err != nil {
			return 0, s.connError()
		}

		switch typeBuf[0] {
		case frameData:
			n, err := s.readDataFrame(conn, p)
			if err != nil {
				return 0, err
			}
			if n == 0 {
				// Duplicate frame was discarded — read next frame.
				continue
			}
			return n, nil
		case frameACK:
			if err := s.readACKFrame(conn); err != nil {
				return 0, err
			}
			// ACK consumed; loop to read next frame.
			continue
		case frameClose:
			// Peer is shutting down intentionally — not a reconnectable event.
			return 0, ErrClosed
		default:
			// Unknown frame type — connection is corrupt.
			return 0, s.connError()
		}
	}
}

// readDataFrame reads the rest of a data frame after the type byte.
// Returns (0, nil) if the frame was a duplicate and was discarded.
func (s *ReliableStream) readDataFrame(conn net.Conn, p []byte) (int, error) {
	var hdr [12]byte // seq(8) + len(4)
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return 0, s.connError()
	}

	seq := binary.BigEndian.Uint64(hdr[:8])
	payloadLen := binary.BigEndian.Uint32(hdr[8:12])

	if payloadLen == 0 || payloadLen > maxFramePayload {
		return 0, s.connError()
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return 0, s.connError()
	}

	// Deduplication: discard frames we've already delivered.
	// The ackLoop will ACK it so the peer frees its buffer.
	if seq < s.recvSeq.Load() {
		return 0, nil
	}

	// Deliver to application and advance the high-water mark.
	s.recvSeq.Store(seq + 1)
	n := copy(p, payload)
	if n < len(payload) {
		s.readLeft = payload[n:]
	}

	// ACK is sent by the background ackLoop — no inline write here.
	// This avoids deadlock with synchronous pipes (net.Pipe).

	return n, nil
}

// readACKFrame reads the rest of an ACK frame after the type byte.
func (s *ReliableStream) readACKFrame(conn net.Conn) error {
	var buf [8]byte
	if _, err := io.ReadFull(conn, buf[:]); err != nil {
		return s.connError()
	}
	ackSeq := binary.BigEndian.Uint64(buf[:])

	if ackSeq > s.peerAck.Load() {
		s.peerAck.Store(ackSeq)
	}
	s.sendBuf.freeTo(ackSeq)
	return nil
}

// Write sends application data through the stream. Large writes are
// automatically chunked into maxFramePayload-sized frames. Returns
// ErrConnLost if the connection is broken or ErrBufFull if the retransmit
// buffer is exhausted (session unrecoverable).
func (s *ReliableStream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if s.isClosed() {
		return 0, ErrClosed
	}
	if s.isConnLost() {
		return 0, ErrConnLost
	}

	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxFramePayload {
			chunk = chunk[:maxFramePayload]
		}

		n, err := s.writeFrame(chunk)
		total += n
		if err != nil {
			return total, err
		}
		p = p[n:]
	}
	return total, nil
}

// writeFrame sends a single data frame. Called with writeMu held.
func (s *ReliableStream) writeFrame(payload []byte) (int, error) {
	seq := s.sendSeq

	// Build the wire frame: type(1) + seq(8) + len(4) + payload
	frame := make([]byte, dataHeaderSize+len(payload))
	frame[0] = frameData
	binary.BigEndian.PutUint64(frame[1:9], seq)
	binary.BigEndian.PutUint32(frame[9:13], uint32(len(payload)))
	copy(frame[13:], payload)

	// Buffer for retransmit BEFORE sending — even if the send fails,
	// the frame is in the buffer for retransmit after reconnection.
	if err := s.sendBuf.add(seq, frame); err != nil {
		return 0, ErrBufFull
	}

	s.sendSeq = seq + 1

	conn := s.getConn()
	if _, err := conn.Write(frame); err != nil {
		return len(payload), s.connError()
	}

	return len(payload), nil
}

// writeACK sends an ACK frame. Acquires writeMu to serialize with data writes.
func (s *ReliableStream) writeACK(seq uint64) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if s.isConnLost() || s.isClosed() {
		return
	}

	var buf [ackFrameSize]byte
	buf[0] = frameACK
	binary.BigEndian.PutUint64(buf[1:], seq)

	conn := s.getConn()
	// Best-effort — if write fails, ackLoop retries next tick.
	_, _ = conn.Write(buf[:])
}

// ackLoop periodically sends ACK frames so the peer can free its retransmit
// buffer, even when no data is flowing in the reverse direction.
func (s *ReliableStream) ackLoop() {
	defer close(s.ackDone)
	ticker := time.NewTicker(ackInterval)
	defer ticker.Stop()

	var lastSent uint64
	for {
		select {
		case <-s.ackStop:
			return
		case <-ticker.C:
			if s.isClosed() || s.isConnLost() {
				continue
			}

			cur := s.recvSeq.Load()
			if cur > 1 && cur-1 != lastSent {
				s.writeACK(cur - 1)
				lastSent = cur - 1
			}
		}
	}
}

// Reconnect swaps the underlying connection and performs the handshake:
// both sides exchange their next-expected sequence, then retransmit any
// unACK'd frames. Call this after both the Read and Write goroutines have
// returned ErrConnLost.
func (s *ReliableStream) Reconnect(newConn net.Conn) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.readMu.Lock()
	defer s.readMu.Unlock()

	if s.closed {
		return ErrClosed
	}

	// Swap connection.
	s.connMu.Lock()
	oldConn := s.conn
	s.conn = newConn
	s.connLost = false
	s.connMu.Unlock()

	// Close old connection (may already be dead).
	if oldConn != nil {
		_ = oldConn.Close()
	}

	// Clear any partial read state — incomplete frames are discarded.
	s.readLeft = nil

	// --- Handshake: exchange next-expected sequence numbers ---
	//
	// Both sides write then read. With synchronous connections (net.Pipe),
	// this would deadlock if both tried to write sequentially — each write
	// blocks until the peer reads, but neither is reading yet. We solve
	// this by writing in a goroutine while reading on the main thread.
	// With real TCP connections, kernel buffers make this unnecessary, but
	// the goroutine approach is safe for all net.Conn implementations.

	recvSeq := s.recvSeq.Load()

	// Build outgoing handshake.
	var outHS [handshakeSize]byte
	outHS[0] = frameHandshake
	binary.BigEndian.PutUint64(outHS[1:], recvSeq)

	// Set deadline for the entire handshake exchange.
	if err := newConn.SetDeadline(time.Now().Add(reconnectTimeout)); err != nil {
		return fmt.Errorf("%w: set deadline: %v", ErrHandshake, err)
	}

	// Write our handshake in a goroutine.
	hsCh := make(chan error, 1)
	go func() {
		_, err := newConn.Write(outHS[:])
		hsCh <- err
	}()

	// Read peer's recvSeq (tells us what to retransmit).
	var inHS [handshakeSize]byte
	if _, err := io.ReadFull(newConn, inHS[:]); err != nil {
		<-hsCh // prevent goroutine leak
		return fmt.Errorf("%w: read handshake: %v", ErrHandshake, err)
	}
	if inHS[0] != frameHandshake {
		<-hsCh
		return fmt.Errorf("%w: unexpected frame type 0x%02x", ErrHandshake, inHS[0])
	}

	// Wait for our handshake write to complete.
	if err := <-hsCh; err != nil {
		return fmt.Errorf("%w: send handshake: %v", ErrHandshake, err)
	}

	peerRecvSeq := binary.BigEndian.Uint64(inHS[1:])

	// Update peer ACK and free acknowledged data.
	if peerRecvSeq > 1 {
		acked := peerRecvSeq - 1
		if acked > s.peerAck.Load() {
			s.peerAck.Store(acked)
		}
		s.sendBuf.freeTo(acked)
	}

	// --- Retransmit unACK'd frames from peerRecvSeq onwards ---
	frames := s.sendBuf.framesFrom(peerRecvSeq)
	for _, frame := range frames {
		if _, err := newConn.Write(frame); err != nil {
			return fmt.Errorf("%w: retransmit: %v", ErrHandshake, err)
		}
	}

	// Clear deadlines for normal operation.
	_ = newConn.SetWriteDeadline(time.Time{})
	_ = newConn.SetReadDeadline(time.Time{})

	return nil
}

// Close shuts down the stream permanently. It sends a close frame to the peer
// so the peer can distinguish an intentional shutdown from a connection loss.
func (s *ReliableStream) Close() error {
	s.connMu.Lock()
	if s.closed {
		s.connMu.Unlock()
		return nil
	}
	s.closed = true
	conn := s.conn
	s.connMu.Unlock()

	close(s.ackStop)
	<-s.ackDone

	if conn != nil {
		// Best-effort: send close frame so the peer returns ErrClosed (not ErrConnLost).
		// Acquire writeMu to ensure no data/ACK write is in flight.
		// Use a short deadline — we're shutting down and don't want to block.
		s.writeMu.Lock()
		_ = conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		_, _ = conn.Write([]byte{frameClose})
		_ = conn.SetWriteDeadline(time.Time{})
		s.writeMu.Unlock()
		return conn.Close()
	}
	return nil
}

// IsConnLost reports whether the stream's connection is currently broken.
func (s *ReliableStream) IsConnLost() bool {
	return s.isConnLost()
}

// RecvSeq returns the next expected receive sequence (for testing/debugging).
func (s *ReliableStream) RecvSeq() uint64 {
	return s.recvSeq.Load()
}

// SendSeq returns the next send sequence (for testing/debugging).
func (s *ReliableStream) SendSeq() uint64 {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.sendSeq
}

// --- internal helpers ---

func (s *ReliableStream) getConn() net.Conn {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	return s.conn
}

func (s *ReliableStream) isConnLost() bool {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	return s.connLost
}

func (s *ReliableStream) isClosed() bool {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	return s.closed
}

func (s *ReliableStream) markConnLost() {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	s.connLost = true
}

// connError returns ErrClosed if the stream was closed (intentional shutdown),
// or marks the connection as lost and returns ErrConnLost (bridge died).
// This prevents a Close() call from being misinterpreted as a connection loss
// when Read/Write are blocked on the connection at the time of Close().
func (s *ReliableStream) connError() error {
	if s.isClosed() {
		return ErrClosed
	}
	s.markConnLost()
	return ErrConnLost
}

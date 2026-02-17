package dbaudit

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTeeReader_PassThrough(t *testing.T) {
	// Data passes through the TeeReader unchanged.
	data := []byte("hello, this is raw data that the parser ignores")
	r := bytes.NewReader(data)
	eventCh := make(chan QueryEvent, 100)
	parser := NewPostgresParser()
	tee := NewTeeReader(r, parser, eventCh)

	got, err := io.ReadAll(tee)
	require.NoError(t, err)
	require.Equal(t, data, got)
}

func TestTeeReader_CapturesQueries(t *testing.T) {
	// Build a valid PostgreSQL byte stream: startup + query.
	var buf bytes.Buffer

	// Startup message.
	startup := make([]byte, 4+4+1)
	binary.BigEndian.PutUint32(startup[0:4], 9)      // length
	binary.BigEndian.PutUint32(startup[4:8], 196608)  // version 3.0
	startup[8] = 0                                     // empty params
	buf.Write(startup)

	// Simple query: Q message.
	sql := "SELECT 42"
	payload := append([]byte(sql), 0)
	msg := make([]byte, 1+4+len(payload))
	msg[0] = 'Q'
	binary.BigEndian.PutUint32(msg[1:5], uint32(4+len(payload)))
	copy(msg[5:], payload)
	buf.Write(msg)

	eventCh := make(chan QueryEvent, 100)
	parser := NewPostgresParser()
	tee := NewTeeReader(&buf, parser, eventCh)

	got, err := io.ReadAll(tee)
	require.NoError(t, err)

	// Verify data passed through.
	require.Equal(t, len(startup)+len(msg), len(got))

	// Verify event captured.
	close(eventCh)
	var events []QueryEvent
	for ev := range eventCh {
		events = append(events, ev)
	}
	require.Len(t, events, 1)
	require.Equal(t, "SELECT 42", events[0].Query)
}

func TestTeeReader_ChannelFull(t *testing.T) {
	// Data still flows even when the event channel is full (non-blocking send).
	var buf bytes.Buffer

	// Startup.
	startup := make([]byte, 9)
	binary.BigEndian.PutUint32(startup[0:4], 9)
	binary.BigEndian.PutUint32(startup[4:8], 196608)
	startup[8] = 0
	buf.Write(startup)

	// Write many queries to overflow the channel.
	for range 20 {
		sql := "SELECT 1"
		payload := append([]byte(sql), 0)
		msg := make([]byte, 1+4+len(payload))
		msg[0] = 'Q'
		binary.BigEndian.PutUint32(msg[1:5], uint32(4+len(payload)))
		copy(msg[5:], payload)
		buf.Write(msg)
	}

	// Channel buffer of 2 — will overflow for 20 queries.
	eventCh := make(chan QueryEvent, 2)
	parser := NewPostgresParser()
	tee := NewTeeReader(&buf, parser, eventCh)

	// Read all data — this should NOT block despite channel being full.
	got, err := io.ReadAll(tee)
	require.NoError(t, err)
	require.NotEmpty(t, got)

	// Some events captured (at most channel capacity), rest dropped.
	close(eventCh)
	var captured int
	for range eventCh {
		captured++
	}
	require.LessOrEqual(t, captured, 2)
}

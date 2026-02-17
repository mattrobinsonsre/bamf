package sshproxy

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRecording_Header(t *testing.T) {
	rec := NewRecording()
	rec.Start(80, 24, map[string]string{"TERM": "xterm-256color"})

	data := rec.Bytes()
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, 1, "should have exactly the header line")

	var header asciicastHeader
	err := json.Unmarshal([]byte(lines[0]), &header)
	require.NoError(t, err)

	require.Equal(t, 2, header.Version)
	require.Equal(t, 80, header.Width)
	require.Equal(t, 24, header.Height)
	require.Equal(t, "xterm-256color", header.Env["TERM"])
	require.NotZero(t, header.Timestamp)
}

func TestRecording_Output(t *testing.T) {
	rec := NewRecording()
	rec.Start(80, 24, nil)

	rec.Output([]byte("$ ls\r\n"))
	rec.Output([]byte("file1.txt  file2.txt\r\n"))

	data := rec.Bytes()
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, 3, "header + 2 output events")

	// Parse first output event.
	var event1 []any
	err := json.Unmarshal([]byte(lines[1]), &event1)
	require.NoError(t, err)
	require.Len(t, event1, 3)

	elapsed, ok := event1[0].(float64)
	require.True(t, ok)
	require.GreaterOrEqual(t, elapsed, 0.0)

	eventType, ok := event1[1].(string)
	require.True(t, ok)
	require.Equal(t, "o", eventType)

	eventData, ok := event1[2].(string)
	require.True(t, ok)
	require.Equal(t, "$ ls\r\n", eventData)
}

func TestRecording_Resize(t *testing.T) {
	rec := NewRecording()
	rec.Start(80, 24, nil)

	rec.Resize(120, 40)

	data := rec.Bytes()
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, 2, "header + resize event")

	var event []any
	err := json.Unmarshal([]byte(lines[1]), &event)
	require.NoError(t, err)
	require.Equal(t, "r", event[1])
	require.Equal(t, "120x40", event[2])
}

func TestRecording_OutputBeforeStart(t *testing.T) {
	rec := NewRecording()

	// Output before Start should be silently dropped.
	rec.Output([]byte("should be ignored"))

	require.Equal(t, 0, rec.Len())
}

func TestRecording_EmptyOutput(t *testing.T) {
	rec := NewRecording()
	rec.Start(80, 24, nil)

	// Empty output should be ignored.
	rec.Output([]byte{})
	rec.Output(nil)

	data := rec.Bytes()
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, 1, "only header, no events")
}

func TestRecording_Timestamps(t *testing.T) {
	rec := NewRecording()
	rec.Start(80, 24, nil)

	time.Sleep(10 * time.Millisecond)
	rec.Output([]byte("delayed"))

	data := rec.Bytes()
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, 2)

	var event []any
	err := json.Unmarshal([]byte(lines[1]), &event)
	require.NoError(t, err)

	elapsed := event[0].(float64)
	require.Greater(t, elapsed, 0.0, "elapsed time should be positive")
}

func TestNormalizeLF(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"no newlines", "hello", "hello"},
		{"already crlf", "hello\r\nworld\r\n", "hello\r\nworld\r\n"},
		{"bare lf", "hello\nworld\n", "hello\r\nworld\r\n"},
		{"mixed", "hello\r\nworld\n", "hello\r\nworld\r\n"},
		{"leading lf", "\nhello", "\r\nhello"},
		{"consecutive lf", "a\n\nb", "a\r\n\r\nb"},
		{"only lf", "\n", "\r\n"},
		{"only crlf", "\r\n", "\r\n"},
		{"cr without lf", "hello\rworld", "hello\rworld"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, normalizeLF(tt.in))
		})
	}
}

func TestRecording_OutputNormalizesLF(t *testing.T) {
	rec := NewRecording()
	rec.Start(80, 24, nil)

	// Bare \n should be normalized to \r\n in the recording.
	rec.Output([]byte("hello\nworld\n"))

	data := rec.Bytes()
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, 2, "header + 1 output event")

	var event []any
	err := json.Unmarshal([]byte(lines[1]), &event)
	require.NoError(t, err)
	require.Equal(t, "hello\r\nworld\r\n", event[2])
}

func TestRecordingWriter(t *testing.T) {
	rec := NewRecording()
	rec.Start(80, 24, nil)

	var buf bytes.Buffer
	w := newRecordingWriter(&buf, rec)

	n, err := w.Write([]byte("hello"))
	require.NoError(t, err)
	require.Equal(t, 5, n)

	// Data should be written to both the underlying writer and the recording.
	require.Equal(t, "hello", buf.String())

	data := rec.Bytes()
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, 2, "header + output event")
}

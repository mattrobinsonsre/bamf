package sshproxy

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

// Recording captures terminal I/O in asciicast v2 format.
// Thread-safe: multiple goroutines may call Output/Resize concurrently.
//
// Format spec: https://docs.asciinema.org/manual/asciicast/v2/
type Recording struct {
	mu      sync.Mutex
	buf     []byte
	start   time.Time
	width   int
	height  int
	started bool
}

// NewRecording creates a new recording. Call Start() to write the header.
func NewRecording() *Recording {
	return &Recording{}
}

// asciicastHeader is the first line of an asciicast v2 file.
type asciicastHeader struct {
	Version   int               `json:"version"`
	Width     int               `json:"width"`
	Height    int               `json:"height"`
	Timestamp int64             `json:"timestamp"`
	Env       map[string]string `json:"env,omitempty"`
}

// Start writes the asciicast header and marks the recording start time.
// Must be called before Output/Resize. Width and height are initial terminal
// dimensions from the pty-req.
func (r *Recording) Start(width, height int, env map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.start = time.Now()
	r.width = width
	r.height = height
	r.started = true

	header := asciicastHeader{
		Version:   2,
		Width:     width,
		Height:    height,
		Timestamp: r.start.Unix(),
		Env:       env,
	}
	data, _ := json.Marshal(header)
	r.buf = append(r.buf, data...)
	r.buf = append(r.buf, '\n')
}

// EnsureStarted starts the recording if it hasn't been started yet.
// Called on shell/exec to capture output even without a PTY (e.g.,
// `ssh user@host "command"`). Uses default dimensions since there's no
// terminal. This prevents users from bypassing recording by avoiding PTY.
func (r *Recording) EnsureStarted() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started {
		return
	}
	r.start = time.Now()
	r.width = 80
	r.height = 24
	r.started = true

	header := asciicastHeader{
		Version:   2,
		Width:     80,
		Height:    24,
		Timestamp: r.start.Unix(),
	}
	data, _ := json.Marshal(header)
	r.buf = append(r.buf, data...)
	r.buf = append(r.buf, '\n')
}

// Output records terminal output data. Only stdout from the target should
// be recorded (not stdin — avoids capturing passwords).
func (r *Recording) Output(data []byte) {
	if len(data) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started {
		return
	}

	elapsed := time.Since(r.start).Seconds()
	// Normalize bare \n to \r\n for proper terminal playback.
	// PTY sessions normally produce \r\n (terminal driver onlcr),
	// but non-PTY exec sessions or certain targets may output bare \n.
	// Without \r, the asciinema player advances the line without returning
	// to column 0, causing a staircase effect.
	r.writeEvent(elapsed, "o", normalizeLF(string(data)))
}

// normalizeLF converts bare \n (not preceded by \r) to \r\n.
func normalizeLF(s string) string {
	n := len(s)
	if n == 0 {
		return s
	}
	// Fast path: check if any bare \n exists.
	hasBare := false
	for i := 0; i < n; i++ {
		if s[i] == '\n' && (i == 0 || s[i-1] != '\r') {
			hasBare = true
			break
		}
	}
	if !hasBare {
		return s
	}
	// Slow path: build normalized string.
	buf := make([]byte, 0, n+n/4)
	for i := 0; i < n; i++ {
		if s[i] == '\n' && (i == 0 || s[i-1] != '\r') {
			buf = append(buf, '\r')
		}
		buf = append(buf, s[i])
	}
	return string(buf)
}

// Resize records a terminal resize event.
func (r *Recording) Resize(width, height int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started {
		return
	}

	r.width = width
	r.height = height
	elapsed := time.Since(r.start).Seconds()
	r.writeEvent(elapsed, "r", fmt.Sprintf("%dx%d", width, height))
}

// writeEvent appends a single event line. Caller must hold r.mu.
func (r *Recording) writeEvent(elapsed float64, eventType, data string) {
	// Format: [elapsed, "type", "data"]
	line, _ := json.Marshal([]any{elapsed, eventType, data})
	r.buf = append(r.buf, line...)
	r.buf = append(r.buf, '\n')
}

// Bytes returns the complete recording data.
func (r *Recording) Bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]byte, len(r.buf))
	copy(out, r.buf)
	return out
}

// Len returns the current size of the recording in bytes.
func (r *Recording) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.buf)
}

// recordingWriter wraps a writer and captures all written data to a Recording.
// Used to tee target stdout into both the client and the recording.
type recordingWriter struct {
	w         io.Writer
	recording *Recording
}

// newRecordingWriter creates a writer that copies to w and records output.
func newRecordingWriter(w io.Writer, rec *Recording) *recordingWriter {
	return &recordingWriter{w: w, recording: rec}
}

func (rw *recordingWriter) Write(p []byte) (int, error) {
	rw.recording.Output(p)
	return rw.w.Write(p)
}

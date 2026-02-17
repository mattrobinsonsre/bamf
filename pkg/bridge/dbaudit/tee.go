package dbaudit

import "io"

// TeeReader wraps an io.Reader, feeding every read chunk to a Parser
// and sending resulting QueryEvents to a channel. Bytes pass through
// unchanged — this is a passive tap, not a filter.
type TeeReader struct {
	r      io.Reader
	parser Parser
	events chan<- QueryEvent
}

// NewTeeReader creates a TeeReader that taps reads from r, parses them
// with parser, and sends events to the events channel. Events are sent
// non-blocking — if the channel is full, events are dropped rather than
// blocking the data path.
func NewTeeReader(r io.Reader, parser Parser, events chan<- QueryEvent) *TeeReader {
	return &TeeReader{
		r:      r,
		parser: parser,
		events: events,
	}
}

func (t *TeeReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if n > 0 {
		// Feed the bytes to the parser. Copy to avoid aliasing issues
		// if the parser buffers the data.
		chunk := make([]byte, n)
		copy(chunk, p[:n])
		for _, ev := range t.parser.Feed(chunk) {
			// Non-blocking send: drop events if channel is full.
			select {
			case t.events <- ev:
			default:
			}
		}
	}
	return n, err
}

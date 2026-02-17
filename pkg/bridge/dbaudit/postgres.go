package dbaudit

import (
	"encoding/binary"
	"time"
)

// PostgreSQL frontend (client→server) message types.
const (
	pgQuery   byte = 'Q' // Simple query
	pgParse   byte = 'P' // Parse (prepared statement)
	pgBind    byte = 'B' // Bind parameters
	pgExecute byte = 'E' // Execute prepared statement
)

// SSLRequest magic bytes: message length=8, code=80877103.
var sslRequestPayload = []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}

// PostgresParser extracts SQL queries from the PostgreSQL wire protocol.
//
// The PostgreSQL frontend message format is:
//
//	[1-byte type][4-byte length (includes self)][payload]
//
// Exception: the startup message has no type byte:
//
//	[4-byte length][4-byte version (196608 = 3.0)][params...]
type PostgresParser struct {
	buf           []byte
	startupDone   bool
	lastPrepQuery string // most recent Parse query text
}

// NewPostgresParser creates a parser for PostgreSQL wire protocol.
func NewPostgresParser() *PostgresParser {
	return &PostgresParser{}
}

func (p *PostgresParser) Protocol() string { return "postgres" }

// IsSSLRequest checks if the given bytes are an SSLRequest message.
// Used by the bridge to intercept and deny SSL upgrades on -audit resources.
func IsSSLRequest(data []byte) bool {
	if len(data) < 8 {
		return false
	}
	for i := range 8 {
		if data[i] != sslRequestPayload[i] {
			return false
		}
	}
	return true
}

func (p *PostgresParser) Feed(data []byte) []QueryEvent {
	p.buf = append(p.buf, data...)
	var events []QueryEvent

	for {
		if !p.startupDone {
			// Startup message: [4-byte length][4-byte version][params...]
			// No type byte prefix. We need at least 8 bytes for length + version.
			if len(p.buf) < 8 {
				break
			}
			msgLen := int(binary.BigEndian.Uint32(p.buf[0:4]))
			if msgLen < 8 || len(p.buf) < msgLen {
				break
			}
			// Skip the startup message (or SSLRequest/GSSENCRequest).
			p.buf = p.buf[msgLen:]
			p.startupDone = true
			continue
		}

		// Standard message: [1-byte type][4-byte length][payload]
		if len(p.buf) < 5 {
			break
		}

		msgType := p.buf[0]
		msgLen := int(binary.BigEndian.Uint32(p.buf[1:5])) // includes the 4 length bytes
		totalLen := 1 + msgLen                               // type byte + message body

		if msgLen < 4 || len(p.buf) < totalLen {
			break
		}

		payload := p.buf[5:totalLen]
		p.buf = p.buf[totalLen:]

		now := time.Now().UTC()

		switch msgType {
		case pgQuery:
			// Simple query: null-terminated SQL string
			if q := extractNullTerminated(payload); q != "" {
				events = append(events, QueryEvent{
					Timestamp: now,
					Query:     q,
					Type:      QuerySimple,
				})
			}

		case pgParse:
			// Parse: statement_name\0 query\0 [param_types]
			// Skip statement name, extract query.
			rest := skipNullTerminated(payload)
			if rest != nil {
				if q := extractNullTerminated(rest); q != "" {
					p.lastPrepQuery = q
					events = append(events, QueryEvent{
						Timestamp: now,
						Query:     q,
						Type:      QueryPrepare,
					})
				}
			}

		case pgBind:
			// Bind: portal_name\0 statement_name\0 ...
			// We don't extract parameter values (binary format is complex).
			// The prepared query text is captured during Parse.

		case pgExecute:
			// Execute: portal_name\0 max_rows(4 bytes)
			// We note the execution; the query was captured during Parse.
			if p.lastPrepQuery != "" {
				events = append(events, QueryEvent{
					Timestamp: now,
					Query:     p.lastPrepQuery,
					Type:      QueryExecute,
				})
			}
		}
	}

	return events
}

// extractNullTerminated extracts a null-terminated string from the start of data.
func extractNullTerminated(data []byte) string {
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return ""
}

// skipNullTerminated skips past the first null-terminated string and returns the rest.
func skipNullTerminated(data []byte) []byte {
	for i, b := range data {
		if b == 0 {
			if i+1 < len(data) {
				return data[i+1:]
			}
			return nil
		}
	}
	return nil
}

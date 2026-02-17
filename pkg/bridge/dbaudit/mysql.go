package dbaudit

import (
	"encoding/binary"
	"time"
)

// MySQL command types (first byte of payload after packet header).
const (
	mysqlComQuery       byte = 0x03
	mysqlComStmtPrepare byte = 0x16
	mysqlComStmtExecute byte = 0x17
)

// MySQLParser extracts SQL queries from the MySQL wire protocol.
//
// MySQL packet format:
//
//	[3-byte LE length][1-byte sequence_id][payload]
//
// The initial handshake phase (server greeting + client auth response)
// is skipped by counting packets: server greeting is seq=0, client auth
// is seq=1, server OK/ERR is seq=2. After that, the command phase begins.
type MySQLParser struct {
	buf          []byte
	authDone     bool
	packetsSeen  int
	preparedStmt map[uint32]string // stmt_id → query text
}

// NewMySQLParser creates a parser for MySQL wire protocol.
func NewMySQLParser() *MySQLParser {
	return &MySQLParser{
		preparedStmt: make(map[uint32]string),
	}
}

func (p *MySQLParser) Protocol() string { return "mysql" }

func (p *MySQLParser) Feed(data []byte) []QueryEvent {
	p.buf = append(p.buf, data...)
	var events []QueryEvent

	for len(p.buf) >= 4 {
		// MySQL packet header: 3 bytes length (LE) + 1 byte sequence
		payloadLen := int(p.buf[0]) | int(p.buf[1])<<8 | int(p.buf[2])<<16
		// seq := p.buf[3]
		totalLen := 4 + payloadLen

		if len(p.buf) < totalLen {
			break
		}

		payload := p.buf[4:totalLen]
		p.buf = p.buf[totalLen:]
		p.packetsSeen++

		// Skip auth phase: the client→server direction sees the client auth
		// response (packet 2 from client's perspective). We skip the first
		// few packets until auth is complete.
		if !p.authDone {
			// Client auth response is the first client→server packet.
			// After that, there may be auth switch or OK/ERR. We mark auth
			// done after the first command-phase packet (packetsSeen >= 2
			// and payload starts with a valid command byte).
			if p.packetsSeen >= 2 && len(payload) > 0 && isCommandByte(payload[0]) {
				p.authDone = true
			} else {
				continue
			}
		}

		if len(payload) == 0 {
			continue
		}

		now := time.Now().UTC()
		cmd := payload[0]

		switch cmd {
		case mysqlComQuery:
			// COM_QUERY: payload[1:] is the SQL string (no null terminator)
			if len(payload) > 1 {
				events = append(events, QueryEvent{
					Timestamp: now,
					Query:     string(payload[1:]),
					Type:      QueryComQuery,
				})
			}

		case mysqlComStmtPrepare:
			// COM_STMT_PREPARE: payload[1:] is the SQL string
			if len(payload) > 1 {
				query := string(payload[1:])
				events = append(events, QueryEvent{
					Timestamp: now,
					Query:     query,
					Type:      QueryPrepare,
				})
				// Store for later Execute reference — we don't have the stmt_id
				// yet (that comes in the response), so we store by sequence.
				// For simplicity, we store the most recent prepare.
				p.preparedStmt[0] = query
			}

		case mysqlComStmtExecute:
			// COM_STMT_EXECUTE: payload[1:5] is stmt_id (LE uint32)
			if len(payload) >= 5 {
				stmtID := binary.LittleEndian.Uint32(payload[1:5])
				query := p.preparedStmt[stmtID]
				if query == "" {
					// Fall back to most recent prepared query
					query = p.preparedStmt[0]
				}
				if query != "" {
					events = append(events, QueryEvent{
						Timestamp: now,
						Query:     query,
						Type:      QueryExecute,
					})
				}
			}
		}
	}

	return events
}

// isCommandByte checks if a byte is a valid MySQL command in the command phase.
func isCommandByte(b byte) bool {
	// COM_QUERY (0x03), COM_INIT_DB (0x02), COM_FIELD_LIST (0x04),
	// COM_QUIT (0x01), COM_PING (0x0E), COM_STMT_PREPARE (0x16), etc.
	return b >= 0x01 && b <= 0x1F
}

package dbaudit

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// buildMySQLPacket constructs a MySQL packet.
func buildMySQLPacket(seq byte, payload []byte) []byte {
	length := len(payload)
	pkt := make([]byte, 4+length)
	pkt[0] = byte(length)
	pkt[1] = byte(length >> 8)
	pkt[2] = byte(length >> 16)
	pkt[3] = seq
	copy(pkt[4:], payload)
	return pkt
}

func TestMySQLParser_ComQuery(t *testing.T) {
	p := NewMySQLParser()

	// First packet: simulate a client auth response (skipped during auth phase).
	authResponse := buildMySQLPacket(1, []byte{0x85, 0xa6, 0x03, 0x00}) // capability flags
	p.Feed(authResponse)

	// COM_QUERY: cmd byte 0x03 + SQL string
	sql := "SELECT * FROM products WHERE price > 100"
	payload := append([]byte{mysqlComQuery}, []byte(sql)...)
	pkt := buildMySQLPacket(0, payload)

	events := p.Feed(pkt)
	require.Len(t, events, 1)
	require.Equal(t, sql, events[0].Query)
	require.Equal(t, QueryComQuery, events[0].Type)
}

func TestMySQLParser_ComStmtPrepare(t *testing.T) {
	p := NewMySQLParser()

	// Skip auth phase.
	p.Feed(buildMySQLPacket(1, []byte{0x85, 0xa6, 0x03, 0x00}))

	// COM_STMT_PREPARE
	sql := "INSERT INTO orders (user_id, total) VALUES (?, ?)"
	payload := append([]byte{mysqlComStmtPrepare}, []byte(sql)...)
	pkt := buildMySQLPacket(0, payload)

	events := p.Feed(pkt)
	require.Len(t, events, 1)
	require.Equal(t, sql, events[0].Query)
	require.Equal(t, QueryPrepare, events[0].Type)
}

func TestMySQLParser_ComStmtExecute(t *testing.T) {
	p := NewMySQLParser()

	// Skip auth phase.
	p.Feed(buildMySQLPacket(1, []byte{0x85, 0xa6, 0x03, 0x00}))

	// Prepare a statement first.
	sql := "DELETE FROM sessions WHERE expired_at < NOW()"
	prepPayload := append([]byte{mysqlComStmtPrepare}, []byte(sql)...)
	p.Feed(buildMySQLPacket(0, prepPayload))

	// COM_STMT_EXECUTE: cmd(1) + stmt_id(4 LE) + flags(1) + iteration_count(4)
	execPayload := []byte{mysqlComStmtExecute, 0, 0, 0, 0, 0x00, 0x01, 0x00, 0x00, 0x00}
	events := p.Feed(buildMySQLPacket(0, execPayload))

	require.Len(t, events, 1)
	require.Equal(t, sql, events[0].Query)
	require.Equal(t, QueryExecute, events[0].Type)
}

func TestMySQLParser_PartialPacket(t *testing.T) {
	p := NewMySQLParser()

	// Skip auth phase.
	p.Feed(buildMySQLPacket(1, []byte{0x85, 0xa6, 0x03, 0x00}))

	sql := "SELECT version()"
	payload := append([]byte{mysqlComQuery}, []byte(sql)...)
	pkt := buildMySQLPacket(0, payload)

	// Split packet in the middle.
	mid := len(pkt) / 2
	events := p.Feed(pkt[:mid])
	require.Empty(t, events, "partial packet should not produce events")

	events = p.Feed(pkt[mid:])
	require.Len(t, events, 1)
	require.Equal(t, sql, events[0].Query)
}

func TestMySQLParser_SkipsAuthPhase(t *testing.T) {
	p := NewMySQLParser()

	// Client auth response — should not generate events even if it
	// happens to contain bytes matching command types.
	authData := make([]byte, 32)
	authData[0] = mysqlComQuery // could be misinterpreted as a command
	pkt := buildMySQLPacket(1, authData)

	events := p.Feed(pkt)
	require.Empty(t, events, "auth phase packets should not produce events")
}

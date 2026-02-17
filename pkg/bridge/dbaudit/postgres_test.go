package dbaudit

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

// buildPgMessage constructs a PostgreSQL frontend message.
func buildPgMessage(msgType byte, payload []byte) []byte {
	length := uint32(4 + len(payload))
	msg := make([]byte, 1+4+len(payload))
	msg[0] = msgType
	binary.BigEndian.PutUint32(msg[1:5], length)
	copy(msg[5:], payload)
	return msg
}

// buildPgStartup constructs a PostgreSQL startup message (no type byte).
func buildPgStartup() []byte {
	// Version 3.0 = 196608
	params := []byte("user\x00test\x00database\x00mydb\x00\x00")
	length := uint32(4 + 4 + len(params))
	msg := make([]byte, 4+4+len(params))
	binary.BigEndian.PutUint32(msg[0:4], length)
	binary.BigEndian.PutUint32(msg[4:8], 196608) // version 3.0
	copy(msg[8:], params)
	return msg
}

func TestPostgresParser_SimpleQuery(t *testing.T) {
	p := NewPostgresParser()

	// Feed startup message first (required before normal messages).
	startup := buildPgStartup()
	events := p.Feed(startup)
	require.Empty(t, events, "startup should not produce events")

	// Simple query: Q message with null-terminated SQL.
	sql := "SELECT * FROM users WHERE id = 1"
	payload := append([]byte(sql), 0)
	msg := buildPgMessage('Q', payload)

	events = p.Feed(msg)
	require.Len(t, events, 1)
	require.Equal(t, sql, events[0].Query)
	require.Equal(t, QuerySimple, events[0].Type)
}

func TestPostgresParser_PreparedStatement(t *testing.T) {
	p := NewPostgresParser()

	// Feed startup.
	p.Feed(buildPgStartup())

	// Parse message: stmt_name\0 query\0 param_count(2 bytes)
	stmtName := "stmt1"
	query := "INSERT INTO logs (msg) VALUES ($1)"
	payload := append([]byte(stmtName), 0)
	payload = append(payload, []byte(query)...)
	payload = append(payload, 0)
	payload = append(payload, 0, 0) // 0 parameter types
	msg := buildPgMessage('P', payload)

	events := p.Feed(msg)
	require.Len(t, events, 1)
	require.Equal(t, query, events[0].Query)
	require.Equal(t, QueryPrepare, events[0].Type)
}

func TestPostgresParser_Execute(t *testing.T) {
	p := NewPostgresParser()
	p.Feed(buildPgStartup())

	// First, a Parse to set lastPrepQuery.
	query := "UPDATE users SET active = $1 WHERE id = $2"
	parsePayload := append([]byte("s1"), 0)
	parsePayload = append(parsePayload, []byte(query)...)
	parsePayload = append(parsePayload, 0, 0, 0)
	p.Feed(buildPgMessage('P', parsePayload))

	// Execute message: portal_name\0 max_rows(4 bytes)
	execPayload := append([]byte(""), 0)
	execPayload = append(execPayload, 0, 0, 0, 0)
	events := p.Feed(buildPgMessage('E', execPayload))

	require.Len(t, events, 1)
	require.Equal(t, query, events[0].Query)
	require.Equal(t, QueryExecute, events[0].Type)
}

func TestPostgresParser_PartialMessage(t *testing.T) {
	p := NewPostgresParser()
	p.Feed(buildPgStartup())

	sql := "SELECT count(*) FROM orders"
	payload := append([]byte(sql), 0)
	msg := buildPgMessage('Q', payload)

	// Split the message in the middle.
	mid := len(msg) / 2
	events := p.Feed(msg[:mid])
	require.Empty(t, events, "partial message should not produce events")

	events = p.Feed(msg[mid:])
	require.Len(t, events, 1)
	require.Equal(t, sql, events[0].Query)
}

func TestPostgresParser_MultipleMessages(t *testing.T) {
	p := NewPostgresParser()
	p.Feed(buildPgStartup())

	// Concatenate two Q messages.
	sql1 := "SELECT 1"
	sql2 := "SELECT 2"
	msg1 := buildPgMessage('Q', append([]byte(sql1), 0))
	msg2 := buildPgMessage('Q', append([]byte(sql2), 0))

	combined := append(msg1, msg2...)
	events := p.Feed(combined)
	require.Len(t, events, 2)
	require.Equal(t, sql1, events[0].Query)
	require.Equal(t, sql2, events[1].Query)
}

func TestPostgresParser_StartupSkipped(t *testing.T) {
	p := NewPostgresParser()

	// Startup message should not generate events.
	events := p.Feed(buildPgStartup())
	require.Empty(t, events)
	require.True(t, p.startupDone)
}

func TestPostgresParser_SSLRequest(t *testing.T) {
	// SSLRequest: length=8, code=80877103
	data := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}
	require.True(t, IsSSLRequest(data))

	// Not SSLRequest.
	startup := buildPgStartup()
	require.False(t, IsSSLRequest(startup))

	// Too short.
	require.False(t, IsSSLRequest(data[:4]))
}

// Package dbaudit implements passive wire protocol parsing for database
// query audit. It taps the client→server byte stream flowing through
// bridge tunnels and extracts SQL queries from PostgreSQL and MySQL
// wire protocols without terminating the connection.
//
// Unlike ssh-audit (which terminates SSH), database audit preserves the
// reliable stream, so sessions survive bridge failure.
package dbaudit

import "time"

// QueryType classifies how a query was sent.
type QueryType string

const (
	QuerySimple   QueryType = "simple"
	QueryPrepare  QueryType = "prepare"
	QueryExecute  QueryType = "execute"
	QueryComQuery QueryType = "com_query"
)

// QueryEvent represents a single database query captured from the wire protocol.
type QueryEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Query     string    `json:"query"`
	Type      QueryType `json:"type"`
}

// Parser extracts SQL queries from a database wire protocol byte stream.
// Implementations must handle partial messages across Feed() calls.
type Parser interface {
	// Feed processes incoming bytes and returns any complete query events.
	// The bytes are from the client→server direction only.
	Feed(data []byte) []QueryEvent

	// Protocol returns the protocol name (e.g., "postgres", "mysql").
	Protocol() string
}

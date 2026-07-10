// Package logutil provides helpers for safe structured logging.
package logutil

import "strings"

// Safe strips carriage returns and line feeds from an untrusted string so it
// cannot forge or split a log entry (log injection, CWE-117). Values logged as
// slog fields to the JSON handler are already escaped, but sanitizing at the
// source is defense-in-depth (correct even under a text handler) and clears the
// taint flow that code scanning tracks.
func Safe(s string) string {
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

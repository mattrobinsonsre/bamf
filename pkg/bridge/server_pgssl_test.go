package bridge

import (
	"bufio"
	"bytes"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// pgMemConn is an in-memory net.Conn: reads drain from r, writes accumulate in w.
type pgMemConn struct {
	r *bytes.Reader
	w *bytes.Buffer
}

func (c *pgMemConn) Read(p []byte) (int, error)       { return c.r.Read(p) }
func (c *pgMemConn) Write(p []byte) (int, error)      { return c.w.Write(p) }
func (c *pgMemConn) Close() error                     { return nil }
func (c *pgMemConn) LocalAddr() net.Addr              { return pgMemAddr{} }
func (c *pgMemConn) RemoteAddr() net.Addr             { return pgMemAddr{} }
func (c *pgMemConn) SetDeadline(t time.Time) error    { return nil }
func (c *pgMemConn) SetReadDeadline(time.Time) error  { return nil }
func (c *pgMemConn) SetWriteDeadline(time.Time) error { return nil }

type pgMemAddr struct{}

func (pgMemAddr) Network() string { return "mem" }
func (pgMemAddr) String() string  { return "mem" }

// The PostgreSQL SSLRequest: message length=8, request code=80877103.
var pgSSLRequest = []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}

func TestInterceptPostgresSSL_deniesSSLRequest(t *testing.T) {
	// SSLRequest followed by the real startup message — only the 8-byte
	// SSLRequest must be consumed; the startup bytes remain for the tunnel.
	trailer := []byte("STARTUP-MESSAGE")
	input := append(append([]byte{}, pgSSLRequest...), trailer...)
	c := &pgMemConn{r: bytes.NewReader(input), w: &bytes.Buffer{}}
	reader := bufio.NewReader(c)

	err := (&Server{}).interceptPostgresSSL(reader, c, slog.Default())
	require.NoError(t, err)
	require.Equal(t, []byte{'N'}, c.w.Bytes(), "must deny TLS with a single 'N'")

	rest, _ := io.ReadAll(reader)
	require.Equal(t, trailer, rest, "only the SSLRequest is consumed; startup bytes remain")
}

func TestInterceptPostgresSSL_passesThroughNonSSLRequest(t *testing.T) {
	// A normal StartupMessage (not an SSLRequest) must be left untouched.
	startup := []byte{0x00, 0x00, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x00, 'x', 'y'}
	c := &pgMemConn{r: bytes.NewReader(startup), w: &bytes.Buffer{}}
	reader := bufio.NewReader(c)

	err := (&Server{}).interceptPostgresSSL(reader, c, slog.Default())
	require.NoError(t, err)
	require.Empty(t, c.w.Bytes(), "a non-SSLRequest must not be answered")

	rest, _ := io.ReadAll(reader)
	require.Equal(t, startup, rest, "nothing must be consumed")
}

func TestInterceptPostgresSSL_shortStreamErrors(t *testing.T) {
	// Fewer than 8 bytes then EOF — the peek must fail rather than misparse.
	c := &pgMemConn{r: bytes.NewReader([]byte{0x00, 0x00}), w: &bytes.Buffer{}}
	reader := bufio.NewReader(c)

	err := (&Server{}).interceptPostgresSSL(reader, c, slog.Default())
	require.Error(t, err)
}

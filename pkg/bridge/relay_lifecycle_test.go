package bridge

import (
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// trackConn wraps a net.Conn and records whether Close was called, so tests can
// assert the pool's close-vs-detach semantics without relying on net.Pipe's
// blocking Write.
type trackConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *trackConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

// newTrackConn returns a trackConn over one end of a net.Pipe (the other end is
// closed immediately — the tests only care about lifecycle, not I/O).
func newTrackConn(t *testing.T) *trackConn {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = b.Close() })
	return &trackConn{Conn: a}
}

func TestRelayPool_removeConn_removesAndCloses(t *testing.T) {
	pool := NewRelayPool(slog.Default())
	t.Cleanup(pool.CloseAll)

	conn := newTrackConn(t)
	pool.Add("agent-1", conn)
	require.Len(t, pool.conns["agent-1"], 1)
	rc := pool.conns["agent-1"][0]

	pool.removeConn("agent-1", rc)

	require.NotContains(t, pool.conns, "agent-1", "empty pool entry must be deleted")
	require.True(t, conn.closed.Load(), "removeConn must close the connection")
}

func TestRelayPool_removeConn_keepsSiblingsOfSameAgent(t *testing.T) {
	pool := NewRelayPool(slog.Default())
	t.Cleanup(pool.CloseAll)

	c1, c2 := newTrackConn(t), newTrackConn(t)
	pool.Add("agent-1", c1)
	pool.Add("agent-1", c2)
	rc1 := pool.conns["agent-1"][0]

	pool.removeConn("agent-1", rc1)

	require.Len(t, pool.conns["agent-1"], 1, "sibling connection must remain")
	require.Same(t, c2, pool.conns["agent-1"][0].conn.(*trackConn))
	require.True(t, c1.closed.Load())
	require.False(t, c2.closed.Load())
}

func TestRelayPool_detachConn_removesWithoutClosing(t *testing.T) {
	pool := NewRelayPool(slog.Default())
	t.Cleanup(pool.CloseAll)

	conn := newTrackConn(t)
	pool.Add("agent-1", conn)
	rc := pool.conns["agent-1"][0]

	pool.detachConn("agent-1", rc)

	require.NotContains(t, pool.conns, "agent-1", "empty pool entry must be deleted")
	require.False(t, conn.closed.Load(), "detachConn must NOT close the connection")
}

func TestRelayPool_reapIdle_closesOnlyIdleConns(t *testing.T) {
	pool := NewRelayPool(slog.Default())
	t.Cleanup(pool.CloseAll)

	idle, fresh := newTrackConn(t), newTrackConn(t)
	pool.Add("idle-agent", idle)
	pool.Add("fresh-agent", fresh)
	// Age the idle connection past the reap threshold; leave the fresh one recent.
	pool.conns["idle-agent"][0].lastActive = time.Now().Add(-2 * relayIdleTimeout)

	pool.reapIdle()

	require.NotContains(t, pool.conns, "idle-agent", "idle agent entry must be removed")
	require.True(t, idle.closed.Load(), "idle connection must be closed")
	require.Contains(t, pool.conns, "fresh-agent", "recent connection must survive")
	require.False(t, fresh.closed.Load())
}

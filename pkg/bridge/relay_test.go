package bridge

import (
	"log/slog"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRelayPool_Detach_RemovesWithoutClosing(t *testing.T) {
	pool := NewRelayPool(slog.Default())
	defer pool.CloseAll()

	// Create a pipe to use as a relay connection
	server, client := net.Pipe()
	defer server.Close()

	pool.Add("agent-1", client)
	require.Equal(t, 1, pool.Count(), "pool should have 1 connection")

	// Detach should return the connection and remove from pool
	detached := pool.Detach("agent-1")
	require.NotNil(t, detached, "Detach should return the connection")
	require.Equal(t, 0, pool.Count(), "pool should be empty after Detach")

	// The connection should still be usable (not closed).
	// net.Pipe is synchronous: Write blocks until the other end Reads,
	// so we must run the write in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		_, err := detached.conn.Write([]byte("hello"))
		errCh <- err
	}()

	// Read from the other end to confirm data arrived
	buf := make([]byte, 5)
	_, err := server.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "hello", string(buf))

	// Verify the write completed without error
	require.NoError(t, <-errCh, "detached connection should still be writable")

	detached.conn.Close()
}

func TestRelayPool_Detach_NonexistentAgent(t *testing.T) {
	pool := NewRelayPool(slog.Default())
	defer pool.CloseAll()

	detached := pool.Detach("nonexistent-agent")
	require.Nil(t, detached, "Detach should return nil for unknown agent")
}

func TestRelayPool_Detach_AgentNotInAcquire(t *testing.T) {
	pool := NewRelayPool(slog.Default())
	defer pool.CloseAll()

	_, client := net.Pipe()

	pool.Add("agent-1", client)
	pool.Detach("agent-1")

	// After Detach, acquire should return (nil, false)
	rc, ok := pool.acquire("agent-1")
	require.False(t, ok, "acquire should return false after Detach")
	require.Nil(t, rc, "acquire should return nil after Detach")
}

func TestRelayPool_Detach_DoesNotAffectOtherAgents(t *testing.T) {
	pool := NewRelayPool(slog.Default())
	defer pool.CloseAll()

	_, client1 := net.Pipe()
	_, client2 := net.Pipe()

	pool.Add("agent-1", client1)
	pool.Add("agent-2", client2)
	require.Equal(t, 2, pool.Count())

	pool.Detach("agent-1")
	require.Equal(t, 1, pool.Count(), "only agent-1 should be removed")

	rc2, ok := pool.acquire("agent-2")
	require.True(t, ok, "agent-2 should still be in the pool")
	require.NotNil(t, rc2, "agent-2 should still be in the pool")
	rc2.mu.Unlock()
}

func TestRelayPool_Remove_ClosesConnection(t *testing.T) {
	pool := NewRelayPool(slog.Default())
	defer pool.CloseAll()

	_, client := net.Pipe()

	pool.Add("agent-1", client)
	pool.Remove("agent-1")

	// Connection should be closed — write should fail
	_, err := client.Write([]byte("hello"))
	require.Error(t, err, "connection should be closed after Remove")
}

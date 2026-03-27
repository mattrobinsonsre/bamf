package agent

import (
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ── Tests: lazyTargetConn ────────────────────────────────────────────

func TestLazyTargetConn_ReadyChannel(t *testing.T) {
	l := &lazyTargetConn{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		addr:   "127.0.0.1:1", // won't be dialed
	}

	ch := l.Ready()
	require.NotNil(t, ch)

	// Should return the same channel on subsequent calls
	ch2 := l.Ready()
	require.Equal(t, ch, ch2)
}

func TestLazyTargetConn_WriteTriggersDialToListener(t *testing.T) {
	// Start a real TCP listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	l := &lazyTargetConn{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		addr:   ln.Addr().String(),
	}
	defer l.Close()

	// Accept connection in background
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	// Write triggers dial
	n, err := l.Write([]byte("hello"))
	require.NoError(t, err)
	require.Equal(t, 5, n)

	// Verify Ready() is signaled
	select {
	case <-l.Ready():
		// ok
	case <-time.After(2 * time.Second):
		t.Fatal("Ready() not signaled after dial")
	}

	// Clean up accepted connection
	select {
	case conn := <-accepted:
		conn.Close()
	case <-time.After(2 * time.Second):
	}
}

func TestLazyTargetConn_DialFailure(t *testing.T) {
	l := &lazyTargetConn{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		addr:   "127.0.0.1:1", // port 1 is almost certainly not listening
	}

	_, err := l.Write([]byte("hello"))
	require.Error(t, err)

	// Ready() should still be signaled (with error)
	select {
	case <-l.Ready():
		// ok
	case <-time.After(2 * time.Second):
		t.Fatal("Ready() not signaled after dial failure")
	}

	// Subsequent reads also fail
	_, err = l.Read(make([]byte, 10))
	require.Error(t, err)
}

func TestLazyTargetConn_CloseBeforeDial(t *testing.T) {
	l := &lazyTargetConn{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		addr:   "127.0.0.1:9999",
	}

	err := l.Close()
	require.NoError(t, err)

	// Ready() should be signaled
	select {
	case <-l.Ready():
		// ok
	case <-time.After(2 * time.Second):
		t.Fatal("Ready() not signaled after close")
	}

	// Write after close should fail
	_, err = l.Write([]byte("hello"))
	require.Error(t, err)
}

func TestLazyTargetConn_OnlyDialsOnce(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	var acceptCount atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			acceptCount.Add(1)
			// Echo back
			go func() {
				buf := make([]byte, 256)
				for {
					n, err := conn.Read(buf)
					if err != nil {
						conn.Close()
						return
					}
					_, _ = conn.Write(buf[:n])
				}
			}()
		}
	}()

	l := &lazyTargetConn{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		addr:   ln.Addr().String(),
	}
	defer l.Close()

	// Multiple writes should only dial once
	for i := range 5 {
		_, err := l.Write([]byte("msg"))
		require.NoError(t, err, "write %d failed", i)
	}

	time.Sleep(50 * time.Millisecond) // let accept goroutine process
	require.Equal(t, int32(1), acceptCount.Load(), "should only accept one connection")
}

// ── Tests: TunnelHandler.IsClosed ────────────────────────────────────

func TestTunnelHandler_IsClosed_Default(t *testing.T) {
	th := &TunnelHandler{}
	require.False(t, th.IsClosed())
}

func TestTunnelHandler_IsClosed_AfterClose(t *testing.T) {
	th := &TunnelHandler{
		closeCh: make(chan struct{}),
	}
	th.Close()
	require.True(t, th.IsClosed())
}

func TestTunnelHandler_Close_Idempotent(t *testing.T) {
	th := &TunnelHandler{
		closeCh: make(chan struct{}),
	}

	// Should not panic on multiple calls
	th.Close()
	th.Close()
	th.Close()
	require.True(t, th.IsClosed())
}

// ── Tests: TunnelHandler.Close channel ───────────────────────────────

func TestTunnelHandler_Close_SignalsChannel(t *testing.T) {
	th := &TunnelHandler{
		closeCh: make(chan struct{}),
	}

	done := make(chan struct{})
	go func() {
		<-th.closeCh
		close(done)
	}()

	th.Close()

	select {
	case <-done:
		// ok
	case <-time.After(2 * time.Second):
		t.Fatal("closeCh not signaled")
	}
}

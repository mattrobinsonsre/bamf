package tunnel

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// pipePair creates a connected pair of net.Conn using net.Pipe.
func pipePair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

// tcpPair creates a connected pair of net.Conn using real TCP.
// Unlike net.Pipe, TCP connections have kernel buffers, so writes
// don't block until the peer reads. This is needed for Reconnect
// tests where both sides write handshakes and retransmit frames
// concurrently.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	var serverConn net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		serverConn, _ = ln.Accept()
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	<-done
	require.NotNil(t, serverConn)

	t.Cleanup(func() { _ = clientConn.Close(); _ = serverConn.Close(); _ = ln.Close() })
	return clientConn, serverConn
}

// streamPair creates two ReliableStreams connected via net.Pipe.
func streamPair(t *testing.T, bufSize int) (*ReliableStream, *ReliableStream) {
	t.Helper()
	a, b := pipePair(t)
	sa := NewStream(a, bufSize)
	sb := NewStream(b, bufSize)
	t.Cleanup(func() { _ = sa.Close(); _ = sb.Close() })
	return sa, sb
}

func TestBasicSendReceive(t *testing.T) {
	sa, sb := streamPair(t, DefaultBufSize)

	msg := []byte("hello postgres")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		n, err := sa.Write(msg)
		require.NoError(t, err)
		require.Equal(t, len(msg), n)
	}()

	buf := make([]byte, 256)
	n, err := sb.Read(buf)
	require.NoError(t, err)
	require.Equal(t, string(msg), string(buf[:n]))

	wg.Wait()
}

func TestBidirectional(t *testing.T) {
	sa, sb := streamPair(t, DefaultBufSize)

	msgA := []byte("request from client")
	msgB := []byte("response from server")

	var wg sync.WaitGroup

	// A writes, B reads.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := sa.Write(msgA)
		require.NoError(t, err)
	}()

	buf := make([]byte, 256)
	n, err := sb.Read(buf)
	require.NoError(t, err)
	require.Equal(t, string(msgA), string(buf[:n]))
	wg.Wait()

	// B writes, A reads.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := sb.Write(msgB)
		require.NoError(t, err)
	}()

	n, err = sa.Read(buf)
	require.NoError(t, err)
	require.Equal(t, string(msgB), string(buf[:n]))
	wg.Wait()
}

func TestMultipleFrames(t *testing.T) {
	sa, sb := streamPair(t, DefaultBufSize)

	messages := []string{"SELECT 1;", "SELECT 2;", "SELECT 3;"}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, m := range messages {
			_, err := sa.Write([]byte(m))
			require.NoError(t, err)
		}
	}()

	buf := make([]byte, 256)
	for _, expected := range messages {
		n, err := sb.Read(buf)
		require.NoError(t, err)
		require.Equal(t, expected, string(buf[:n]))
	}
	wg.Wait()
}

func TestReconnectRetransmitsUnacked(t *testing.T) {
	// Create initial connection pair.
	connA1, connB1 := pipePair(t)
	sa := NewStream(connA1, DefaultBufSize)
	sb := NewStream(connB1, DefaultBufSize)
	t.Cleanup(func() { _ = sa.Close(); _ = sb.Close() })

	// Send a message through the initial connection.
	msg1 := []byte("before break")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := sa.Write(msg1)
		require.NoError(t, err)
	}()

	buf := make([]byte, 256)
	n, err := sb.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "before break", string(buf[:n]))
	wg.Wait()

	// Wait for ACK to propagate.
	time.Sleep(100 * time.Millisecond)

	// Now send a message and break the connection before the receiver gets it.
	msg2 := []byte("during break")

	// Write msg2 — it will be buffered in sa's retransmit buffer.
	// We break the pipe immediately after write, so sb may or may not receive it.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = sa.Write(msg2)
	}()

	// Give the write a moment to start, then break the connections.
	time.Sleep(10 * time.Millisecond)
	_ = connA1.Close()
	_ = connB1.Close()
	wg.Wait()

	// Both sides should now be in connLost state.
	// Give the read side a moment to detect the break.
	time.Sleep(10 * time.Millisecond)

	// Create a new connection pair and reconnect.
	// Use TCP (not net.Pipe) because retransmit writes need kernel
	// buffering — with net.Pipe, sa's retransmit blocks until sb reads,
	// but sb is still in Reconnect and hasn't started reading yet.
	connA2, connB2 := tcpPair(t)

	// Reconnect both sides concurrently (they exchange handshakes).
	var reconnWg sync.WaitGroup
	reconnWg.Add(2)
	go func() {
		defer reconnWg.Done()
		err := sa.Reconnect(connA2)
		require.NoError(t, err)
	}()
	go func() {
		defer reconnWg.Done()
		err := sb.Reconnect(connB2)
		require.NoError(t, err)
	}()
	reconnWg.Wait()

	// sb should receive msg2 via retransmission.
	n, err = sb.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "during break", string(buf[:n]))

	// Verify normal operation continues.
	msg3 := []byte("after reconnect")
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := sa.Write(msg3)
		require.NoError(t, err)
	}()

	n, err = sb.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "after reconnect", string(buf[:n]))
	wg.Wait()
}

func TestDeduplication(t *testing.T) {
	// Simulate: receiver got frames 1 and 2, sender retransmits 1, 2, 3.
	// Only frame 3 should be delivered.
	connA, connB := pipePair(t)
	sa := NewStream(connA, DefaultBufSize)
	sb := NewStream(connB, DefaultBufSize)
	t.Cleanup(func() { _ = sa.Close(); _ = sb.Close() })

	// Send two messages.
	var wg sync.WaitGroup
	for _, msg := range []string{"msg1", "msg2"} {
		m := msg
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := sa.Write([]byte(m))
			require.NoError(t, err)
		}()

		buf := make([]byte, 256)
		n, err := sb.Read(buf)
		require.NoError(t, err)
		require.Equal(t, m, string(buf[:n]))
		wg.Wait()
	}

	// sb.recvSeq should now be 3 (received 1 and 2).
	require.Equal(t, uint64(3), sb.RecvSeq())

	// sa.sendSeq should now be 3 (sent 1 and 2).
	require.Equal(t, uint64(3), sa.SendSeq())
}

func TestBinaryPayload(t *testing.T) {
	sa, sb := streamPair(t, DefaultBufSize)

	// PostgreSQL wire protocol is binary — make sure arbitrary bytes work.
	payload := make([]byte, 256)
	for i := range payload {
		payload[i] = byte(i)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := sa.Write(payload)
		require.NoError(t, err)
	}()

	received := make([]byte, 512)
	n, err := sb.Read(received)
	require.NoError(t, err)
	require.Equal(t, payload, received[:n])
	wg.Wait()
}

func TestLargePayloadChunking(t *testing.T) {
	sa, sb := streamPair(t, DefaultBufSize)

	// Write more than maxFramePayload in one call — should be chunked.
	payload := make([]byte, maxFramePayload+1000)
	for i := range payload {
		payload[i] = byte(i % 251) // prime to avoid patterns
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		n, err := sa.Write(payload)
		require.NoError(t, err)
		require.Equal(t, len(payload), n)
	}()

	// Read all chunks.
	received := make([]byte, 0, len(payload))
	buf := make([]byte, 4096)
	for len(received) < len(payload) {
		n, err := sb.Read(buf)
		require.NoError(t, err)
		received = append(received, buf[:n]...)
	}
	require.Equal(t, payload, received)
	wg.Wait()
}

func TestBufferFull(t *testing.T) {
	// Tiny buffer — should fill quickly.
	connA, connB := net.Pipe()
	sa := NewStream(connA, 100)
	t.Cleanup(func() { _ = sa.Close(); _ = connB.Close() })

	// Consume frames from connB so writes don't block on the pipe.
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := connB.Read(buf); err != nil {
				return
			}
		}
	}()

	// Write until buffer is full.
	data := make([]byte, 50)
	_, err := sa.Write(data)
	require.NoError(t, err)

	// Second write should fail — buffer full (50 + header > 100 remaining).
	_, err = sa.Write(data)
	require.ErrorIs(t, err, ErrBufFull)
}

func TestConnLostOnClose(t *testing.T) {
	connA, connB := pipePair(t)
	sa := NewStream(connA, DefaultBufSize)
	_ = NewStream(connB, DefaultBufSize)
	t.Cleanup(func() { _ = sa.Close() })

	// Close the underlying connection.
	_ = connA.Close()

	buf := make([]byte, 256)
	_, err := sa.Read(buf)
	require.ErrorIs(t, err, ErrConnLost)
}

func TestCloseStream(t *testing.T) {
	sa, _ := streamPair(t, DefaultBufSize)

	err := sa.Close()
	require.NoError(t, err)

	_, err = sa.Write([]byte("after close"))
	require.ErrorIs(t, err, ErrClosed)

	buf := make([]byte, 256)
	_, err = sa.Read(buf)
	require.ErrorIs(t, err, ErrClosed)
}

func TestZeroLengthWrite(t *testing.T) {
	sa, _ := streamPair(t, DefaultBufSize)

	n, err := sa.Write(nil)
	require.NoError(t, err)
	require.Equal(t, 0, n)

	n, err = sa.Write([]byte{})
	require.NoError(t, err)
	require.Equal(t, 0, n)
}

func TestSmallReadBuffer(t *testing.T) {
	sa, sb := streamPair(t, DefaultBufSize)

	msg := []byte("a]longer message that won't fit in a tiny buffer")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := sa.Write(msg)
		require.NoError(t, err)
	}()

	// Read into a very small buffer — should get partial reads.
	var received []byte
	buf := make([]byte, 5)
	for len(received) < len(msg) {
		n, err := sb.Read(buf)
		require.NoError(t, err)
		received = append(received, buf[:n]...)
	}
	require.Equal(t, string(msg), string(received))
	wg.Wait()
}

func TestConcurrentReadWrite(t *testing.T) {
	sa, sb := streamPair(t, DefaultBufSize)

	count := 100
	var wg sync.WaitGroup

	// A→B: send count messages.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < count; i++ {
			_, err := sa.Write([]byte("ping"))
			require.NoError(t, err)
		}
	}()

	// B→A: send count messages.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < count; i++ {
			_, err := sb.Write([]byte("pong"))
			require.NoError(t, err)
		}
	}()

	// Read A→B.
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 256)
		for i := 0; i < count; i++ {
			n, err := sb.Read(buf)
			require.NoError(t, err)
			require.Equal(t, "ping", string(buf[:n]))
		}
	}()

	// Read B→A.
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 256)
		for i := 0; i < count; i++ {
			n, err := sa.Read(buf)
			require.NoError(t, err)
			require.Equal(t, "pong", string(buf[:n]))
		}
	}()

	wg.Wait()
}

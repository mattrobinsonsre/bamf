package webterm

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// blockingRWC: a ReadWriteCloser that blocks on Read until data is written
// or Close is called. Useful for simulating an agent-side channel where
// output arrives asynchronously.
// ---------------------------------------------------------------------------

type blockingRWC struct {
	mu       sync.Mutex
	cond     *sync.Cond
	buf      bytes.Buffer
	closed   bool
	written  bytes.Buffer // captures writes
	writeErr error        // injected error for Write
}

func newBlockingRWC() *blockingRWC {
	b := &blockingRWC{}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (b *blockingRWC) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for b.buf.Len() == 0 && !b.closed {
		b.cond.Wait()
	}
	if b.closed && b.buf.Len() == 0 {
		return 0, io.EOF
	}
	return b.buf.Read(p)
}

func (b *blockingRWC) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, io.ErrClosedPipe
	}
	if b.writeErr != nil {
		return 0, b.writeErr
	}
	return b.written.Write(p)
}

func (b *blockingRWC) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	b.cond.Broadcast()
	return nil
}

// push injects data that will be returned by Read.
func (b *blockingRWC) push(data []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Write(data)
	b.cond.Signal()
}

// getWritten returns a copy of all data written to the blockingRWC.
func (b *blockingRWC) getWritten() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]byte, b.written.Len())
	copy(out, b.written.Bytes())
	return out
}

// ---------------------------------------------------------------------------
// NewSession tests — constructor field verification
// ---------------------------------------------------------------------------

func TestNewSession_FieldsInitialized(t *testing.T) {
	clientConn, remote := net.Pipe()
	defer clientConn.Close()
	defer remote.Close()

	agentIO := newBlockingRWC()
	logger := slog.Default()

	s := NewSession("sess-001", "web-db", clientConn, agentIO, logger)
	defer s.Close()

	require.Equal(t, "sess-001", s.ID)
	require.Equal(t, "web-db", s.Protocol)
	require.NotNil(t, s.ringBuf, "ring buffer should be allocated")
	require.NotNil(t, s.reconnectCh, "reconnectCh should be created")
	require.NotNil(t, s.closeCh, "closeCh should be created")
	require.NotNil(t, s.WarnCh, "WarnCh should be created")
	require.False(t, s.IsDetached(), "new session should not be detached")
	require.False(t, s.closed.Load(), "new session should not be closed")
	require.Nil(t, s.resizeFn, "resizeFn should be nil by default")
}

func TestNewSession_RingBufferCapacity(t *testing.T) {
	clientConn, remote := net.Pipe()
	defer clientConn.Close()
	defer remote.Close()

	agentIO := newBlockingRWC()
	s := NewSession("sess-cap", "web-ssh", clientConn, agentIO, slog.Default())
	defer s.Close()

	// Ring buffer should accept DefaultRingBufSize bytes.
	data := make([]byte, DefaultRingBufSize)
	for i := range data {
		data[i] = byte(i % 256)
	}
	n, err := s.ringBuf.Write(data)
	require.NoError(t, err)
	require.Equal(t, DefaultRingBufSize, n)
	require.Equal(t, DefaultRingBufSize, s.ringBuf.Len())
}

func TestNewSession_ReconnectChBuffered(t *testing.T) {
	clientConn, remote := net.Pipe()
	defer clientConn.Close()
	defer remote.Close()

	agentIO := newBlockingRWC()
	s := NewSession("sess-ch", "web-ssh", clientConn, agentIO, slog.Default())
	defer s.Close()

	require.Equal(t, 1, cap(s.reconnectCh))
}

func TestNewSession_WarnChBuffered(t *testing.T) {
	clientConn, remote := net.Pipe()
	defer clientConn.Close()
	defer remote.Close()

	agentIO := newBlockingRWC()
	s := NewSession("sess-warn", "web-ssh", clientConn, agentIO, slog.Default())
	defer s.Close()

	require.Equal(t, 8, cap(s.WarnCh))
}

func TestNewSession_DifferentProtocols(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
	}{
		{name: "web-ssh", protocol: "web-ssh"},
		{name: "web-db", protocol: "web-db"},
		{name: "empty protocol", protocol: ""},
		{name: "custom protocol", protocol: "custom-proto"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, remote := net.Pipe()
			defer clientConn.Close()
			defer remote.Close()

			agentIO := newBlockingRWC()
			s := NewSession("proto-test", tt.protocol, clientConn, agentIO, slog.Default())
			defer s.Close()

			require.Equal(t, tt.protocol, s.Protocol)
		})
	}
}

// ---------------------------------------------------------------------------
// SetResizeFunc tests
// ---------------------------------------------------------------------------

func TestSetResizeFunc_StoredAndCallable(t *testing.T) {
	clientConn, remote := net.Pipe()
	defer clientConn.Close()
	defer remote.Close()

	agentIO := newBlockingRWC()
	s := NewSession("resize-test", "web-ssh", clientConn, agentIO, slog.Default())
	defer s.Close()

	var calls []struct{ cols, rows uint16 }
	s.SetResizeFunc(func(cols, rows uint16) {
		calls = append(calls, struct{ cols, rows uint16 }{cols, rows})
	})

	require.NotNil(t, s.resizeFn)

	s.resizeFn(80, 24)
	s.resizeFn(120, 40)
	s.resizeFn(200, 60)

	require.Len(t, calls, 3)
	require.Equal(t, uint16(80), calls[0].cols)
	require.Equal(t, uint16(24), calls[0].rows)
	require.Equal(t, uint16(120), calls[1].cols)
	require.Equal(t, uint16(40), calls[1].rows)
	require.Equal(t, uint16(200), calls[2].cols)
	require.Equal(t, uint16(60), calls[2].rows)
}

func TestSetResizeFunc_OverwritesPrevious(t *testing.T) {
	clientConn, remote := net.Pipe()
	defer clientConn.Close()
	defer remote.Close()

	agentIO := newBlockingRWC()
	s := NewSession("resize-overwrite", "web-ssh", clientConn, agentIO, slog.Default())
	defer s.Close()

	var firstCalled bool
	s.SetResizeFunc(func(cols, rows uint16) {
		firstCalled = true
	})

	var secondCalled bool
	s.SetResizeFunc(func(cols, rows uint16) {
		secondCalled = true
	})

	s.resizeFn(80, 24)
	require.False(t, firstCalled, "first resize func should be overwritten")
	require.True(t, secondCalled, "second resize func should be called")
}

func TestSetResizeFunc_NilResetsToNil(t *testing.T) {
	clientConn, remote := net.Pipe()
	defer clientConn.Close()
	defer remote.Close()

	agentIO := newBlockingRWC()
	s := NewSession("resize-nil", "web-ssh", clientConn, agentIO, slog.Default())
	defer s.Close()

	s.SetResizeFunc(func(cols, rows uint16) {})
	require.NotNil(t, s.resizeFn)

	s.SetResizeFunc(nil)
	require.Nil(t, s.resizeFn)
}

// ---------------------------------------------------------------------------
// IsDetached tests
// ---------------------------------------------------------------------------

func TestIsDetached_InitiallyFalse(t *testing.T) {
	clientConn, remote := net.Pipe()
	defer clientConn.Close()
	defer remote.Close()

	agentIO := newBlockingRWC()
	s := NewSession("detach-init", "web-ssh", clientConn, agentIO, slog.Default())
	defer s.Close()

	require.False(t, s.IsDetached())
}

func TestIsDetached_ReflectsAtomicState(t *testing.T) {
	clientConn, remote := net.Pipe()
	defer clientConn.Close()
	defer remote.Close()

	agentIO := newBlockingRWC()
	s := NewSession("detach-atomic", "web-ssh", clientConn, agentIO, slog.Default())
	defer s.Close()

	s.detached.Store(true)
	require.True(t, s.IsDetached())

	s.detached.Store(false)
	require.False(t, s.IsDetached())

	// Toggle multiple times.
	for i := 0; i < 10; i++ {
		s.detached.Store(i%2 == 0)
		require.Equal(t, i%2 == 0, s.IsDetached())
	}
}

// ---------------------------------------------------------------------------
// Reconnect tests
// ---------------------------------------------------------------------------

func TestReconnect_ConnectionDelivered(t *testing.T) {
	clientConn, remote := net.Pipe()
	defer clientConn.Close()
	defer remote.Close()

	agentIO := newBlockingRWC()
	s := NewSession("reconn-deliver", "web-ssh", clientConn, agentIO, slog.Default())
	defer s.Close()

	newA, newB := net.Pipe()
	defer newA.Close()
	defer newB.Close()

	s.Reconnect(newA)

	select {
	case got := <-s.reconnectCh:
		require.Equal(t, newA, got)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for reconnect delivery")
	}
}

func TestReconnect_ChannelFullClosesConnection(t *testing.T) {
	clientConn, remote := net.Pipe()
	defer clientConn.Close()
	defer remote.Close()

	agentIO := newBlockingRWC()
	s := NewSession("reconn-full", "web-ssh", clientConn, agentIO, slog.Default())
	defer s.Close()

	firstA, firstB := net.Pipe()
	defer firstA.Close()
	defer firstB.Close()

	secondA, secondB := net.Pipe()
	defer secondB.Close()

	// Fill the channel (capacity 1).
	s.Reconnect(firstA)

	// Second call should not block; connection is closed by Reconnect.
	s.Reconnect(secondA)

	// Verify first is still in channel.
	got := <-s.reconnectCh
	require.Equal(t, firstA, got)

	// secondA should be closed — writing to it should fail.
	_, err := secondA.Write([]byte("test"))
	require.Error(t, err, "second connection should be closed when channel is full")
}

// ---------------------------------------------------------------------------
// Close tests
// ---------------------------------------------------------------------------

func TestClose_ClosesAgentIO(t *testing.T) {
	clientConn, remote := net.Pipe()
	defer remote.Close()

	agentIO := newBlockingRWC()
	s := NewSession("close-agent", "web-ssh", clientConn, agentIO, slog.Default())

	s.Close()

	agentIO.mu.Lock()
	require.True(t, agentIO.closed, "agentIO should be closed")
	agentIO.mu.Unlock()
}

func TestClose_ClosesClientConn(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientB.Close()

	agentIO := newBlockingRWC()
	s := NewSession("close-client", "web-ssh", clientA, agentIO, slog.Default())

	s.Close()

	// clientA should be closed — reading from clientB (other end) should fail.
	buf := make([]byte, 1)
	_, err := clientB.Read(buf)
	require.Error(t, err, "client conn should be closed after session Close")
}

func TestClose_IdempotentMultipleCalls(t *testing.T) {
	clientConn, remote := net.Pipe()
	defer remote.Close()

	agentIO := newBlockingRWC()
	s := NewSession("close-idem", "web-ssh", clientConn, agentIO, slog.Default())

	// Call Close multiple times — should not panic.
	for i := 0; i < 5; i++ {
		s.Close()
	}

	require.True(t, s.closed.Load())
}

func TestClose_SetsClosedFlag(t *testing.T) {
	clientConn, remote := net.Pipe()
	defer remote.Close()

	agentIO := newBlockingRWC()
	s := NewSession("close-flag", "web-ssh", clientConn, agentIO, slog.Default())

	require.False(t, s.closed.Load())
	s.Close()
	require.True(t, s.closed.Load())
}

func TestClose_ClosesCloseCh(t *testing.T) {
	clientConn, remote := net.Pipe()
	defer remote.Close()

	agentIO := newBlockingRWC()
	s := NewSession("close-ch", "web-ssh", clientConn, agentIO, slog.Default())

	s.Close()

	// closeCh should be closed — select should resolve immediately.
	select {
	case <-s.closeCh:
		// expected
	case <-time.After(time.Second):
		t.Fatal("closeCh should be closed after Close()")
	}
}

func TestClose_NilClientConnDoesNotPanic(t *testing.T) {
	agentIO := newBlockingRWC()
	s := &Session{
		ID:          "close-nil-client",
		Protocol:    "web-ssh",
		logger:      slog.Default(),
		agentIO:     agentIO,
		clientConn:  nil, // simulate nil clientConn
		ringBuf:     NewRingBuffer(DefaultRingBufSize),
		reconnectCh: make(chan net.Conn, 1),
		closeCh:     make(chan struct{}),
		WarnCh:      make(chan string, 8),
	}

	// Should not panic even with nil clientConn.
	s.Close()
	require.True(t, s.closed.Load())
}

// ---------------------------------------------------------------------------
// SendWarning tests
// ---------------------------------------------------------------------------

func TestSendWarning_DeliveredToWarnCh(t *testing.T) {
	clientConn, remote := net.Pipe()
	defer clientConn.Close()
	defer remote.Close()

	agentIO := newBlockingRWC()
	s := NewSession("warn-deliver", "web-ssh", clientConn, agentIO, slog.Default())
	defer s.Close()

	s.SendWarning("draining in 30s")

	select {
	case msg := <-s.WarnCh:
		require.Equal(t, "draining in 30s", msg)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for warning")
	}
}

func TestSendWarning_MultipleMessages(t *testing.T) {
	clientConn, remote := net.Pipe()
	defer clientConn.Close()
	defer remote.Close()

	agentIO := newBlockingRWC()
	s := NewSession("warn-multi", "web-ssh", clientConn, agentIO, slog.Default())
	defer s.Close()

	messages := []string{"msg1", "msg2", "msg3"}
	for _, m := range messages {
		s.SendWarning(m)
	}

	for _, expected := range messages {
		select {
		case msg := <-s.WarnCh:
			require.Equal(t, expected, msg)
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for warning %q", expected)
		}
	}
}

func TestSendWarning_DropsWhenBufferFull(t *testing.T) {
	clientConn, remote := net.Pipe()
	defer clientConn.Close()
	defer remote.Close()

	agentIO := newBlockingRWC()
	s := NewSession("warn-full", "web-ssh", clientConn, agentIO, slog.Default())
	defer s.Close()

	// Fill WarnCh buffer (capacity 8).
	for i := 0; i < 8; i++ {
		s.SendWarning("fill")
	}

	// This should not block — message is silently dropped.
	done := make(chan struct{})
	go func() {
		s.SendWarning("dropped")
		close(done)
	}()

	select {
	case <-done:
		// Good — did not block.
	case <-time.After(time.Second):
		t.Fatal("SendWarning blocked when channel was full")
	}

	require.Len(t, s.WarnCh, 8, "channel should still have exactly 8 messages")
}

func TestSendWarning_EmptyString(t *testing.T) {
	clientConn, remote := net.Pipe()
	defer clientConn.Close()
	defer remote.Close()

	agentIO := newBlockingRWC()
	s := NewSession("warn-empty", "web-ssh", clientConn, agentIO, slog.Default())
	defer s.Close()

	s.SendWarning("")

	select {
	case msg := <-s.WarnCh:
		require.Equal(t, "", msg)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for empty warning")
	}
}

// ---------------------------------------------------------------------------
// waitForReconnect tests
// ---------------------------------------------------------------------------

func TestWaitForReconnect_SuccessfulReconnect(t *testing.T) {
	clientConn, remote := net.Pipe()
	defer clientConn.Close()
	defer remote.Close()

	agentIO := newBlockingRWC()
	s := NewSession("wait-success", "web-ssh", clientConn, agentIO, slog.Default())
	defer s.Close()

	newA, newB := net.Pipe()
	defer newA.Close()
	defer newB.Close()

	// Send reconnect before calling waitForReconnect.
	go func() {
		time.Sleep(50 * time.Millisecond)
		s.reconnectCh <- newA
	}()

	conn, ok := s.waitForReconnect()
	require.True(t, ok)
	require.Equal(t, newA, conn)
	require.True(t, s.IsDetached(), "should be detached during waitForReconnect")
}

func TestWaitForReconnect_CloseCancels(t *testing.T) {
	clientConn, remote := net.Pipe()
	defer clientConn.Close()
	defer remote.Close()

	agentIO := newBlockingRWC()
	s := NewSession("wait-close", "web-ssh", clientConn, agentIO, slog.Default())

	// Close in a goroutine after a small delay.
	go func() {
		time.Sleep(50 * time.Millisecond)
		s.Close()
	}()

	conn, ok := s.waitForReconnect()
	require.False(t, ok)
	require.Nil(t, conn)
}

func TestWaitForReconnect_SetsDetached(t *testing.T) {
	clientConn, remote := net.Pipe()
	defer clientConn.Close()
	defer remote.Close()

	agentIO := newBlockingRWC()
	s := NewSession("wait-detach", "web-ssh", clientConn, agentIO, slog.Default())

	require.False(t, s.IsDetached())

	// Close immediately to prevent timeout delay.
	go func() {
		time.Sleep(20 * time.Millisecond)
		s.Close()
	}()

	s.waitForReconnect()
	require.True(t, s.IsDetached(), "waitForReconnect should set detached to true")
}

// ---------------------------------------------------------------------------
// Run / runConnected tests — bidirectional relay
// ---------------------------------------------------------------------------

// runSession starts s.Run() in a goroutine and returns a channel that receives
// the result. The caller must ensure the session eventually terminates.
func runSession(s *Session) <-chan error {
	ch := make(chan error, 1)
	go func() { ch <- s.Run() }()
	return ch
}

// awaitRun waits for Run to finish within the given timeout.
func awaitRun(t *testing.T, runCh <-chan error, timeout time.Duration) {
	t.Helper()
	select {
	case <-runCh:
	case <-time.After(timeout):
		t.Fatal("Run did not exit within timeout")
	}
}

func TestRun_DataFromClientToAgent(t *testing.T) {
	clientA, clientB := net.Pipe()
	agentIO := newBlockingRWC()

	s := NewSession("run-c2a", "web-ssh", clientA, agentIO, slog.Default())
	runCh := runSession(s)

	// Write a data frame from the client side.
	fw := NewFrameWriter(clientB)
	require.NoError(t, fw.WriteData([]byte("hello agent")))

	// Give the session loop time to relay the data.
	time.Sleep(50 * time.Millisecond)

	// Verify agent received the data.
	written := agentIO.getWritten()
	require.Contains(t, string(written), "hello agent")

	// Terminate: close session (closes agentIO + client, exits Run loop).
	s.Close()
	awaitRun(t, runCh, 2*time.Second)
}

func TestRun_DataFromAgentToClient(t *testing.T) {
	clientA, clientB := net.Pipe()
	agentIO := newBlockingRWC()

	s := NewSession("run-a2c", "web-ssh", clientA, agentIO, slog.Default())
	runCh := runSession(s)

	// Push data from the agent side.
	agentIO.push([]byte("server output"))

	// Read the frame from the client side.
	fr := NewFrameReader(clientB)
	typ, payload, err := fr.ReadFrame()
	require.NoError(t, err)
	require.Equal(t, FrameData, typ)
	require.Equal(t, "server output", string(payload))

	s.Close()
	awaitRun(t, runCh, 2*time.Second)
}

func TestRun_ResizeFrameCallsResizeFunc(t *testing.T) {
	clientA, clientB := net.Pipe()
	agentIO := newBlockingRWC()

	s := NewSession("run-resize", "web-ssh", clientA, agentIO, slog.Default())

	var resizeMu sync.Mutex
	var gotCols, gotRows uint16
	s.SetResizeFunc(func(cols, rows uint16) {
		resizeMu.Lock()
		gotCols = cols
		gotRows = rows
		resizeMu.Unlock()
	})

	runCh := runSession(s)

	// Send a resize frame from the client.
	fw := NewFrameWriter(clientB)
	require.NoError(t, fw.WriteResize(132, 50))

	// Wait for the resize to be processed.
	require.Eventually(t, func() bool {
		resizeMu.Lock()
		defer resizeMu.Unlock()
		return gotCols == 132 && gotRows == 50
	}, 2*time.Second, 10*time.Millisecond)

	s.Close()
	awaitRun(t, runCh, 2*time.Second)
}

func TestRun_ResizeFrameWithoutResizeFuncDoesNotPanic(t *testing.T) {
	clientA, clientB := net.Pipe()
	agentIO := newBlockingRWC()

	s := NewSession("run-resize-nil", "web-ssh", clientA, agentIO, slog.Default())
	// Deliberately not setting resizeFn.

	runCh := runSession(s)

	// Send a resize frame — should not panic even without resizeFn.
	fw := NewFrameWriter(clientB)
	require.NoError(t, fw.WriteResize(80, 24))

	// Give time for processing.
	time.Sleep(50 * time.Millisecond)

	s.Close()
	awaitRun(t, runCh, 2*time.Second)
}

func TestRun_StatusFrameIgnored(t *testing.T) {
	clientA, clientB := net.Pipe()
	agentIO := newBlockingRWC()

	s := NewSession("run-status-ignore", "web-ssh", clientA, agentIO, slog.Default())
	runCh := runSession(s)

	fw := NewFrameWriter(clientB)

	// Send a status frame from client — should be silently ignored.
	require.NoError(t, fw.WriteStatus("unexpected-from-client"))
	// Also send a data frame to prove the session is still working.
	require.NoError(t, fw.WriteData([]byte("still alive")))

	time.Sleep(50 * time.Millisecond)

	// Agent should have received the data frame (not the status).
	written := string(agentIO.getWritten())
	require.Contains(t, written, "still alive")

	s.Close()
	awaitRun(t, runCh, 2*time.Second)
}

func TestRun_CloseTerminatesRunLoop(t *testing.T) {
	clientA, _ := net.Pipe()
	agentIO := newBlockingRWC()

	s := NewSession("run-close-term", "web-ssh", clientA, agentIO, slog.Default())
	runCh := runSession(s)

	// Give Run a moment to start.
	time.Sleep(50 * time.Millisecond)

	s.Close()
	awaitRun(t, runCh, 2*time.Second)
}

func TestRun_ClientDisconnectTriggersDetach(t *testing.T) {
	clientA, clientB := net.Pipe()
	agentIO := newBlockingRWC()

	s := NewSession("run-detach", "web-ssh", clientA, agentIO, slog.Default())
	runCh := runSession(s)

	// Push data so the agent→client goroutine is actively writing.
	agentIO.push([]byte("output"))
	time.Sleep(50 * time.Millisecond)

	// Close the client to trigger disconnection.
	clientB.Close()

	// Session should enter detached state.
	require.Eventually(t, func() bool {
		return s.IsDetached()
	}, 2*time.Second, 10*time.Millisecond, "session should become detached")

	// Close to exit the reconnect wait loop.
	s.Close()
	awaitRun(t, runCh, 5*time.Second)
}

func TestRun_MultipleDataFrames(t *testing.T) {
	clientA, clientB := net.Pipe()
	agentIO := newBlockingRWC()

	s := NewSession("run-multi", "web-ssh", clientA, agentIO, slog.Default())
	runCh := runSession(s)

	// Send multiple data frames.
	fw := NewFrameWriter(clientB)
	messages := []string{"line 1\n", "line 2\n", "line 3\n"}
	for _, msg := range messages {
		require.NoError(t, fw.WriteData([]byte(msg)))
	}

	time.Sleep(100 * time.Millisecond)

	written := string(agentIO.getWritten())
	for _, msg := range messages {
		require.Contains(t, written, msg)
	}

	s.Close()
	awaitRun(t, runCh, 2*time.Second)
}

func TestRun_BinaryDataPreserved(t *testing.T) {
	clientA, clientB := net.Pipe()
	agentIO := newBlockingRWC()

	s := NewSession("run-binary", "web-ssh", clientA, agentIO, slog.Default())
	runCh := runSession(s)

	// Send binary data with null bytes and high bytes.
	binaryData := []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0x00, 0x80}
	fw := NewFrameWriter(clientB)
	require.NoError(t, fw.WriteData(binaryData))

	time.Sleep(50 * time.Millisecond)

	written := agentIO.getWritten()
	require.Equal(t, binaryData, written)

	s.Close()
	awaitRun(t, runCh, 2*time.Second)
}

func TestRun_LargeDataFrame(t *testing.T) {
	clientA, clientB := net.Pipe()
	agentIO := newBlockingRWC()

	s := NewSession("run-large", "web-ssh", clientA, agentIO, slog.Default())
	runCh := runSession(s)

	// Send a large data frame (32KB).
	largeData := make([]byte, 32*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}
	fw := NewFrameWriter(clientB)
	require.NoError(t, fw.WriteData(largeData))

	time.Sleep(100 * time.Millisecond)

	written := agentIO.getWritten()
	require.Equal(t, largeData, written)

	s.Close()
	awaitRun(t, runCh, 2*time.Second)
}

func TestRun_AgentOutputContinuousStream(t *testing.T) {
	clientA, clientB := net.Pipe()
	agentIO := newBlockingRWC()

	s := NewSession("run-stream", "web-ssh", clientA, agentIO, slog.Default())
	runCh := runSession(s)

	// Push chunks one at a time, reading each frame before pushing the next.
	// This avoids coalescing where the session reads multiple chunks in one
	// Read call and writes a single frame.
	fr := NewFrameReader(clientB)
	expected := []string{"chunk-1 ", "chunk-2 ", "chunk-3"}

	for _, chunk := range expected {
		agentIO.push([]byte(chunk))

		typ, payload, err := fr.ReadFrame()
		require.NoError(t, err)
		require.Equal(t, FrameData, typ)
		require.Equal(t, chunk, string(payload))
	}

	s.Close()
	awaitRun(t, runCh, 2*time.Second)
}

// ---------------------------------------------------------------------------
// Drain warning during active session
// ---------------------------------------------------------------------------

func TestRun_DrainWarningDuringActiveSession(t *testing.T) {
	clientA, clientB := net.Pipe()
	agentIO := newBlockingRWC()

	s := NewSession("run-drain-warn", "web-ssh", clientA, agentIO, slog.Default())
	runCh := runSession(s)

	// Give the session loop time to start monitoring WarnCh.
	time.Sleep(50 * time.Millisecond)

	// Send a drain warning.
	s.SendWarning("bridge-0 draining in 60s")

	// The warning should be sent as a status frame to the client.
	fr := NewFrameReader(clientB)
	typ, payload, err := fr.ReadFrame()
	require.NoError(t, err)
	require.Equal(t, FrameStatus, typ)
	require.Equal(t, "warn:bridge-0 draining in 60s", string(payload))

	s.Close()
	awaitRun(t, runCh, 2*time.Second)
}

// ---------------------------------------------------------------------------
// Reconnection with ring buffer drain tests
// ---------------------------------------------------------------------------

func TestRun_ReconnectDrainsRingBuffer(t *testing.T) {
	clientA, clientB := net.Pipe()
	agentIO := newBlockingRWC()

	s := NewSession("run-reconn-drain", "web-ssh", clientA, agentIO, slog.Default())
	runCh := runSession(s)

	// Push some data from agent.
	agentIO.push([]byte("before-disconnect"))

	// Read that data on the client side so we know the session is active.
	fr := NewFrameReader(clientB)
	typ, payload, err := fr.ReadFrame()
	require.NoError(t, err)
	require.Equal(t, FrameData, typ)
	require.Equal(t, "before-disconnect", string(payload))

	// Close the client to trigger detach.
	clientB.Close()

	// Wait for detach.
	require.Eventually(t, func() bool {
		return s.IsDetached()
	}, 2*time.Second, 10*time.Millisecond)

	// While detached, push more data — it should be buffered in ring buffer.
	agentIO.push([]byte("buffered-output"))
	time.Sleep(100 * time.Millisecond)

	// Create a new client connection and reconnect.
	newClientA, newClientB := net.Pipe()
	defer newClientB.Close()

	s.Reconnect(newClientA)

	// Read frames from new client: expect "resumed" status + buffered data.
	fr2 := NewFrameReader(newClientB)

	// First frame should be a status "resumed".
	typ, payload, err = fr2.ReadFrame()
	require.NoError(t, err)
	require.Equal(t, FrameStatus, typ)
	require.Equal(t, "resumed", string(payload))

	// Second frame should contain the buffered data.
	typ, payload, err = fr2.ReadFrame()
	require.NoError(t, err)
	require.Equal(t, FrameData, typ)
	require.Contains(t, string(payload), "buffered-output")

	// Clean up.
	s.Close()
	awaitRun(t, runCh, 5*time.Second)
}

func TestRun_ReconnectWithEmptyRingBuffer(t *testing.T) {
	clientA, clientB := net.Pipe()
	agentIO := newBlockingRWC()

	s := NewSession("run-reconn-empty", "web-ssh", clientA, agentIO, slog.Default())
	runCh := runSession(s)

	// Give session time to start.
	time.Sleep(50 * time.Millisecond)

	// Close the client to trigger detach (no data pushed — ring buffer empty).
	clientB.Close()

	require.Eventually(t, func() bool {
		return s.IsDetached()
	}, 2*time.Second, 10*time.Millisecond)

	// Reconnect with no buffered data.
	newClientA, newClientB := net.Pipe()
	defer newClientB.Close()

	s.Reconnect(newClientA)

	// Should only get "resumed" status — no data frame for empty ring buffer.
	fr := NewFrameReader(newClientB)
	typ, payload, err := fr.ReadFrame()
	require.NoError(t, err)
	require.Equal(t, FrameStatus, typ)
	require.Equal(t, "resumed", string(payload))

	// Verify session is no longer detached after reconnect completes.
	require.Eventually(t, func() bool {
		return !s.IsDetached()
	}, 2*time.Second, 10*time.Millisecond)

	s.Close()
	awaitRun(t, runCh, 5*time.Second)
}

// ---------------------------------------------------------------------------
// Concurrent access safety
// ---------------------------------------------------------------------------

func TestSession_ConcurrentOperations(t *testing.T) {
	clientConn, remote := net.Pipe()
	defer clientConn.Close()
	defer remote.Close()

	agentIO := newBlockingRWC()
	s := NewSession("concurrent", "web-ssh", clientConn, agentIO, slog.Default())
	defer s.Close()

	var wg sync.WaitGroup
	var closedOnce atomic.Bool

	// Concurrent IsDetached reads.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.IsDetached()
		}()
	}

	// Concurrent detached state toggles.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			s.detached.Store(n%2 == 0)
		}(i)
	}

	// Concurrent SendWarning calls.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.SendWarning("concurrent-warning")
		}()
	}

	// Concurrent Reconnect calls (only one will succeed, others close the conn).
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c1, c2 := net.Pipe()
			defer c2.Close()
			s.Reconnect(c1)
		}()
	}

	// Single Close to avoid double-close of closeCh.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if closedOnce.CompareAndSwap(false, true) {
			s.Close()
		}
	}()

	wg.Wait()
	// If we get here without a panic or data race, the test passes.
}

// ---------------------------------------------------------------------------
// runConnected edge cases
// ---------------------------------------------------------------------------

func TestRunConnected_ClearsDetachedFlag(t *testing.T) {
	// runConnected should set detached=false at entry.
	clientA, clientB := net.Pipe()
	defer clientB.Close()

	agentIO := newBlockingRWC()
	s := NewSession("rc-clear", "web-ssh", clientA, agentIO, slog.Default())

	// Pre-set detached to true.
	s.detached.Store(true)

	// Run in background — runConnected resets detached.
	runCh := runSession(s)

	require.Eventually(t, func() bool {
		return !s.IsDetached()
	}, time.Second, 10*time.Millisecond, "runConnected should clear detached flag")

	s.Close()
	awaitRun(t, runCh, 2*time.Second)
}

func TestRun_MixedFrameTypes(t *testing.T) {
	clientA, clientB := net.Pipe()
	agentIO := newBlockingRWC()

	var resizeMu sync.Mutex
	var resizeCols, resizeRows uint16

	s := NewSession("run-mixed", "web-ssh", clientA, agentIO, slog.Default())
	s.SetResizeFunc(func(cols, rows uint16) {
		resizeMu.Lock()
		resizeCols = cols
		resizeRows = rows
		resizeMu.Unlock()
	})

	runCh := runSession(s)

	fw := NewFrameWriter(clientB)

	// Send data, then resize, then status (ignored), then more data.
	require.NoError(t, fw.WriteData([]byte("first")))
	require.NoError(t, fw.WriteResize(100, 50))
	require.NoError(t, fw.WriteStatus("ignore-me"))
	require.NoError(t, fw.WriteData([]byte("second")))

	time.Sleep(100 * time.Millisecond)

	// Check resize was called.
	resizeMu.Lock()
	require.Equal(t, uint16(100), resizeCols)
	require.Equal(t, uint16(50), resizeRows)
	resizeMu.Unlock()

	// Check agent received both data frames.
	written := string(agentIO.getWritten())
	require.Contains(t, written, "first")
	require.Contains(t, written, "second")

	s.Close()
	awaitRun(t, runCh, 2*time.Second)
}

func TestRun_AgentIOCloseExitsRun(t *testing.T) {
	// When agentIO closes and client is still open, Run should eventually exit.
	// runConnected sees agentIO EOF; if detached is false, it returns the error
	// (agentIO read), which Run considers a non-nil return and enters the detach
	// loop. We then close the session to complete.
	clientA, clientB := net.Pipe()
	defer clientB.Close()

	agentIO := newBlockingRWC()
	s := NewSession("run-agent-eof", "web-ssh", clientA, agentIO, slog.Default())
	runCh := runSession(s)

	// Close agentIO — the agentIO→client goroutine gets EOF.
	agentIO.Close()

	// The session may enter detached state if the client reader error arrives
	// after the agentIO error. Close the session to ensure exit.
	time.Sleep(100 * time.Millisecond)
	s.Close()

	awaitRun(t, runCh, 2*time.Second)
}

// ---------------------------------------------------------------------------
// Bidirectional flow test
// ---------------------------------------------------------------------------

func TestRun_BidirectionalRelay(t *testing.T) {
	clientA, clientB := net.Pipe()
	agentIO := newBlockingRWC()

	s := NewSession("run-bidir", "web-ssh", clientA, agentIO, slog.Default())
	runCh := runSession(s)

	// Client sends data to agent.
	fw := NewFrameWriter(clientB)
	require.NoError(t, fw.WriteData([]byte("client->agent")))

	time.Sleep(50 * time.Millisecond)
	require.Contains(t, string(agentIO.getWritten()), "client->agent")

	// Agent sends data to client.
	agentIO.push([]byte("agent->client"))

	fr := NewFrameReader(clientB)
	typ, payload, err := fr.ReadFrame()
	require.NoError(t, err)
	require.Equal(t, FrameData, typ)
	require.Equal(t, "agent->client", string(payload))

	s.Close()
	awaitRun(t, runCh, 2*time.Second)
}

package webterm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewRingBuffer(t *testing.T) {
	rb := NewRingBuffer(1024)
	require.NotNil(t, rb)
	require.Equal(t, 0, rb.Len())
}

func TestRingBuffer_WriteSmall(t *testing.T) {
	rb := NewRingBuffer(64)
	n, err := rb.Write([]byte("hello"))
	require.NoError(t, err)
	require.Equal(t, 5, n)
	require.Equal(t, 5, rb.Len())
}

func TestRingBuffer_WriteEmpty(t *testing.T) {
	rb := NewRingBuffer(64)
	n, err := rb.Write([]byte{})
	require.NoError(t, err)
	require.Equal(t, 0, n)
	require.Equal(t, 0, rb.Len())
}

func TestRingBuffer_ReadAllEmpty(t *testing.T) {
	rb := NewRingBuffer(64)
	data := rb.ReadAll()
	require.Nil(t, data)
}

func TestRingBuffer_WriteAndReadAll(t *testing.T) {
	rb := NewRingBuffer(64)
	_, err := rb.Write([]byte("hello world"))
	require.NoError(t, err)

	data := rb.ReadAll()
	require.Equal(t, "hello world", string(data))

	// After ReadAll, buffer is reset
	require.Equal(t, 0, rb.Len())
	require.Nil(t, rb.ReadAll())
}

func TestRingBuffer_MultipleWrites(t *testing.T) {
	rb := NewRingBuffer(64)
	_, _ = rb.Write([]byte("hello "))
	_, _ = rb.Write([]byte("world"))

	data := rb.ReadAll()
	require.Equal(t, "hello world", string(data))
}

func TestRingBuffer_WrapAround(t *testing.T) {
	// Buffer of size 8
	rb := NewRingBuffer(8)

	// Write 6 bytes
	_, _ = rb.Write([]byte("abcdef"))
	require.Equal(t, 6, rb.Len())

	// Write 5 more bytes — wraps around
	_, _ = rb.Write([]byte("ghijk"))
	require.Equal(t, 8, rb.Len())

	// Should contain the last 8 bytes of "abcdefghijk" = "defghijk"
	data := rb.ReadAll()
	require.Equal(t, "defghijk", string(data))
}

func TestRingBuffer_ExactFill(t *testing.T) {
	rb := NewRingBuffer(5)
	_, _ = rb.Write([]byte("12345"))
	require.Equal(t, 5, rb.Len())

	data := rb.ReadAll()
	require.Equal(t, "12345", string(data))
}

func TestRingBuffer_OverwriteLargerThanBuffer(t *testing.T) {
	rb := NewRingBuffer(4)
	n, err := rb.Write([]byte("abcdefgh"))
	require.NoError(t, err)
	require.Equal(t, 8, n) // reports full write
	require.Equal(t, 4, rb.Len())

	// Only the last 4 bytes are kept
	data := rb.ReadAll()
	require.Equal(t, "efgh", string(data))
}

func TestRingBuffer_LenAfterWrap(t *testing.T) {
	rb := NewRingBuffer(4)
	_, _ = rb.Write([]byte("ab"))
	require.Equal(t, 2, rb.Len())

	_, _ = rb.Write([]byte("cdef"))
	require.Equal(t, 4, rb.Len()) // full after wrap
}

func TestRingBuffer_ResetAfterReadAll(t *testing.T) {
	rb := NewRingBuffer(16)
	_, _ = rb.Write([]byte("first"))
	_ = rb.ReadAll()

	_, _ = rb.Write([]byte("second"))
	data := rb.ReadAll()
	require.Equal(t, "second", string(data))
}

func TestRingBuffer_MultipleWraps(t *testing.T) {
	rb := NewRingBuffer(4)
	// Wrap multiple times
	for i := 0; i < 10; i++ {
		_, _ = rb.Write([]byte("ab"))
	}
	require.Equal(t, 4, rb.Len())
	data := rb.ReadAll()
	require.Equal(t, 4, len(data))
	require.Equal(t, "abab", string(data))
}

func TestRingBuffer_DefaultSize(t *testing.T) {
	require.Equal(t, 64*1024, DefaultRingBufSize)
}

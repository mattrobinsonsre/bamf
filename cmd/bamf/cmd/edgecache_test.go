package cmd

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestEdgeCache_RoundTripAndTTL(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// Cold cache → nil.
	require.Nil(t, loadFreshEdgeRTTs())

	// Write then read back within the TTL.
	require.NoError(t, writeEdgeCache(map[string]int{"eu": 12, "us": 40}))
	got := loadFreshEdgeRTTs()
	require.Equal(t, map[string]int{"eu": 12, "us": 40}, got)
}

func TestEdgeCache_StaleReturnsNil(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	path, err := edgeCachePath()
	require.NoError(t, err)

	// Hand-write a cache older than the TTL.
	stale := edgeCache{MeasuredAt: time.Now().Add(-2 * edgeCacheTTL), RTTs: map[string]int{"eu": 5}}
	data, err := json.Marshal(stale)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, data, 0o600))

	require.Nil(t, loadFreshEdgeRTTs())
}

func TestEdgeCache_EmptyVectorTreatedAsCold(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	require.NoError(t, writeEdgeCache(map[string]int{})) // no measurements
	require.Nil(t, loadFreshEdgeRTTs())
}

func TestProbeEdge_MeasuresReachableTarget(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	host, port := splitHostPort(t, ln.Addr().String())
	rtt, ok := probeEdge(context.Background(), EdgeProbeTarget{Name: "eu", ProbeHost: host, ProbePort: port})
	require.True(t, ok)
	require.GreaterOrEqual(t, rtt, time.Duration(0))
}

func TestProbeEdge_UnreachableFails(t *testing.T) {
	// Reserved TEST-NET-1 address, filtered — connect will time out/refuse.
	rtt, ok := probeEdge(context.Background(), EdgeProbeTarget{Name: "x", ProbeHost: "192.0.2.1", ProbePort: 9})
	require.False(t, ok)
	require.Zero(t, rtt)
}

func TestProbeEdges_OmitsFailures(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	host, port := splitHostPort(t, ln.Addr().String())

	rtts := probeEdges(context.Background(), []EdgeProbeTarget{
		{Name: "up", ProbeHost: host, ProbePort: port},
		{Name: "down", ProbeHost: "192.0.2.1", ProbePort: 9},
	})
	_, hasUp := rtts["up"]
	_, hasDown := rtts["down"]
	require.True(t, hasUp)
	require.False(t, hasDown)
}

func splitHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return host, port
}

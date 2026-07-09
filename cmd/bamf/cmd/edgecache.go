package cmd

// Client-leg latency probe + cache for measured-latency edge selection (#119).
// The CLI probes each candidate edge's regional ingress (TCP-connect timing),
// caches the vector in ~/.bamf/edges.json, and sends it on the next connect so
// the API can pick the true client+agent rendezvous edge. Probing runs in the
// background after a tunnel is up — it never blocks or affects the connection.

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// EdgeProbeTarget is one edge the CLI should latency-probe, delivered in the
// connect response. Mirrors the Python EdgeProbeTarget model.
type EdgeProbeTarget struct {
	Name      string `json:"name"`
	ProbeHost string `json:"probe_host"`
	ProbePort int    `json:"probe_port"`
}

// edgeCacheTTL is how long a measured client-leg vector stays fresh. Within the
// window the CLI reuses the cache and skips probing; after it, the next connect
// triggers a background re-probe.
const edgeCacheTTL = time.Hour

// edgeProbeTimeout bounds a single edge's TCP-connect probe.
const edgeProbeTimeout = 3 * time.Second

// edgeRefreshBudget bounds the whole background probe sweep.
const edgeRefreshBudget = 15 * time.Second

// edgeCache is the on-disk client-leg latency vector (~/.bamf/edges.json).
type edgeCache struct {
	MeasuredAt time.Time      `json:"measured_at"`
	RTTs       map[string]int `json:"rtts"` // edge name → milliseconds
}

func edgeCachePath() (string, error) {
	dir, err := bamfDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "edges.json"), nil
}

// loadFreshEdgeRTTs returns the cached client-leg vector if present and within
// the TTL, else nil. A cold or stale cache yields nil, so the connect request
// carries no client legs and the API routes to the agent-nearest guess.
func loadFreshEdgeRTTs() map[string]int {
	path, err := edgeCachePath()
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var c edgeCache
	if err := json.Unmarshal(data, &c); err != nil {
		return nil
	}
	if len(c.RTTs) == 0 || time.Since(c.MeasuredAt) > edgeCacheTTL {
		return nil
	}
	return c.RTTs
}

// writeEdgeCache atomically persists a measured client-leg vector.
func writeEdgeCache(rtts map[string]int) error {
	path, err := edgeCachePath()
	if err != nil {
		return err
	}
	data, err := json.Marshal(edgeCache{MeasuredAt: time.Now(), RTTs: rtts})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// probeEdge measures TCP-connect latency to one edge's bridge ingress. Each
// edge's regional ingress has a distinct address, so connect time is a per-edge
// client-leg RTT proxy — no TLS/cert handling needed for a latency sample.
func probeEdge(ctx context.Context, target EdgeProbeTarget) (time.Duration, bool) {
	addr := net.JoinHostPort(target.ProbeHost, strconv.Itoa(target.ProbePort))
	dialer := &net.Dialer{Timeout: edgeProbeTimeout}
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, false
	}
	rtt := time.Since(start)
	_ = conn.Close()
	return rtt, true
}

// probeEdges probes all candidates concurrently and returns the measured
// vector (edges whose probe failed are omitted).
func probeEdges(ctx context.Context, candidates []EdgeProbeTarget) map[string]int {
	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		rtts = make(map[string]int, len(candidates))
	)
	for _, target := range candidates {
		wg.Add(1)
		go func(t EdgeProbeTarget) {
			defer wg.Done()
			if rtt, ok := probeEdge(ctx, t); ok {
				mu.Lock()
				rtts[t.Name] = int(rtt.Milliseconds())
				mu.Unlock()
			}
		}(target)
	}
	wg.Wait()
	return rtts
}

// maybeRefreshEdgeCache re-probes the candidate edges and rewrites the cache,
// but only when the cache is stale — a warm CLI does not probe on every
// connect. Safe to run in a detached goroutine after a tunnel is established: it
// never touches the live connection, and a short-lived CLI that exits before it
// finishes simply re-probes next time (the self-selecting property that keeps
// latency work off short sessions).
func maybeRefreshEdgeCache(candidates []EdgeProbeTarget) {
	if len(candidates) == 0 || loadFreshEdgeRTTs() != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), edgeRefreshBudget)
	defer cancel()
	if rtts := probeEdges(ctx, candidates); len(rtts) > 0 {
		_ = writeEdgeCache(rtts)
	}
}

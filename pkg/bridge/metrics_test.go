package bridge

import (
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

func TestNewMetricsProvider(t *testing.T) {
	tm := NewTunnelManager(slog.Default())
	rp := NewRelayPool(slog.Default())
	defer rp.CloseAll()

	mp := newMetricsProvider(tm, rp)
	require.NotNil(t, mp)
	require.NotNil(t, mp.activeTunnels)
	require.NotNil(t, mp.tunnelsByProto)
	require.NotNil(t, mp.activeRelays)
	require.NotNil(t, mp.bytesSentTotal)
	require.NotNil(t, mp.bytesRecvTotal)
	require.NotNil(t, mp.draining)
	require.NotNil(t, mp.nonMigratableTun)
}

func TestMetricsProvider_Describe(t *testing.T) {
	tm := NewTunnelManager(slog.Default())
	rp := NewRelayPool(slog.Default())
	defer rp.CloseAll()

	mp := newMetricsProvider(tm, rp)
	ch := make(chan *prometheus.Desc, 10)
	mp.Describe(ch)
	close(ch)

	var descs []*prometheus.Desc
	for d := range ch {
		descs = append(descs, d)
	}
	require.Len(t, descs, 7, "should describe 7 metrics")
}

func TestMetricsProvider_CollectEmpty(t *testing.T) {
	tm := NewTunnelManager(slog.Default())
	rp := NewRelayPool(slog.Default())
	defer rp.CloseAll()

	mp := newMetricsProvider(tm, rp)
	ch := make(chan prometheus.Metric, 20)
	mp.Collect(ch)
	close(ch)

	metrics := drainMetrics(t, ch)
	// With no tunnels: activeTunnels=0, activeRelays=0, bytesSent=0, bytesRecv=0, draining=0, nonMigratable=0
	// No tunnelsByProto entries (empty map)
	require.GreaterOrEqual(t, len(metrics), 6, "should have at least 6 metrics")

	// Check active tunnels is 0
	for _, m := range metrics {
		desc := m.Desc().String()
		if containsStr(desc, "bamf_bridge_active_tunnels\"") {
			require.Equal(t, float64(0), metricValue(t, m))
		}
		if containsStr(desc, "bamf_bridge_draining") {
			require.Equal(t, float64(0), metricValue(t, m))
		}
	}
}

func TestMetricsProvider_DrainingFlag(t *testing.T) {
	tm := NewTunnelManager(slog.Default())
	rp := NewRelayPool(slog.Default())
	defer rp.CloseAll()

	mp := newMetricsProvider(tm, rp)

	// Initially not draining
	ch := make(chan prometheus.Metric, 20)
	mp.Collect(ch)
	close(ch)
	for m := range ch {
		if containsStr(m.Desc().String(), "bamf_bridge_draining") {
			require.Equal(t, float64(0), metricValue(t, m))
		}
	}

	// Set draining
	mp.isDraining.Store(true)
	ch2 := make(chan prometheus.Metric, 20)
	mp.Collect(ch2)
	close(ch2)
	for m := range ch2 {
		if containsStr(m.Desc().String(), "bamf_bridge_draining") {
			require.Equal(t, float64(1), metricValue(t, m))
		}
	}
}

func TestMetricsProvider_RegistersWithPrometheus(t *testing.T) {
	tm := NewTunnelManager(slog.Default())
	rp := NewRelayPool(slog.Default())
	defer rp.CloseAll()

	mp := newMetricsProvider(tm, rp)

	reg := prometheus.NewRegistry()
	err := reg.Register(mp)
	require.NoError(t, err)

	families, err := reg.Gather()
	require.NoError(t, err)
	require.NotEmpty(t, families)

	// Verify expected metric names
	names := make(map[string]bool)
	for _, f := range families {
		names[f.GetName()] = true
	}
	require.True(t, names["bamf_bridge_active_tunnels"])
	require.True(t, names["bamf_bridge_active_relays"])
	require.True(t, names["bamf_bridge_bytes_sent_total"])
	require.True(t, names["bamf_bridge_bytes_received_total"])
	require.True(t, names["bamf_bridge_draining"])
	require.True(t, names["bamf_bridge_non_migratable_tunnels"])
}

// --- helpers ---

func drainMetrics(t *testing.T, ch <-chan prometheus.Metric) []prometheus.Metric {
	t.Helper()
	var result []prometheus.Metric
	for m := range ch {
		result = append(result, m)
	}
	return result
}

func metricValue(t *testing.T, m prometheus.Metric) float64 {
	t.Helper()
	var d dto.Metric
	err := m.Write(&d)
	require.NoError(t, err)
	if d.Gauge != nil {
		return d.Gauge.GetValue()
	}
	if d.Counter != nil {
		return d.Counter.GetValue()
	}
	t.Fatal("metric is neither gauge nor counter")
	return 0
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && searchStr(s, substr)
}

func searchStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

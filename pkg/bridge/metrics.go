package bridge

import (
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
)

// metricsProvider exposes bridge metrics for Prometheus scraping.
// It implements prometheus.Collector to read live values from TunnelManager
// and RelayPool at scrape time rather than maintaining separate counters.
type metricsProvider struct {
	tunnels *TunnelManager
	relays  *RelayPool

	activeTunnels    *prometheus.Desc
	tunnelsByProto   *prometheus.Desc
	activeRelays     *prometheus.Desc
	bytesSentTotal   *prometheus.Desc
	bytesRecvTotal   *prometheus.Desc
	draining         *prometheus.Desc
	nonMigratableTun *prometheus.Desc

	// draining flag — set by Shutdown(), read at scrape time
	isDraining atomic.Bool
}

func newMetricsProvider(tunnels *TunnelManager, relays *RelayPool) *metricsProvider {
	return &metricsProvider{
		tunnels: tunnels,
		relays:  relays,
		activeTunnels: prometheus.NewDesc(
			"bamf_bridge_active_tunnels",
			"Number of active tunnels on this bridge pod",
			nil, nil,
		),
		tunnelsByProto: prometheus.NewDesc(
			"bamf_bridge_active_tunnels_by_protocol",
			"Number of active tunnels by protocol type",
			[]string{"protocol"}, nil,
		),
		activeRelays: prometheus.NewDesc(
			"bamf_bridge_active_relays",
			"Number of active HTTP relay connections to agents",
			nil, nil,
		),
		bytesSentTotal: prometheus.NewDesc(
			"bamf_bridge_bytes_sent_total",
			"Total bytes sent through tunnels (client to agent)",
			nil, nil,
		),
		bytesRecvTotal: prometheus.NewDesc(
			"bamf_bridge_bytes_received_total",
			"Total bytes received through tunnels (agent to client)",
			nil, nil,
		),
		draining: prometheus.NewDesc(
			"bamf_bridge_draining",
			"Whether this bridge pod is currently draining (1=draining, 0=normal)",
			nil, nil,
		),
		nonMigratableTun: prometheus.NewDesc(
			"bamf_bridge_non_migratable_tunnels",
			"Number of active non-migratable tunnels (ssh-audit)",
			nil, nil,
		),
	}
}

// Describe implements prometheus.Collector.
func (m *metricsProvider) Describe(ch chan<- *prometheus.Desc) {
	ch <- m.activeTunnels
	ch <- m.tunnelsByProto
	ch <- m.activeRelays
	ch <- m.bytesSentTotal
	ch <- m.bytesRecvTotal
	ch <- m.draining
	ch <- m.nonMigratableTun
}

// Collect implements prometheus.Collector.
func (m *metricsProvider) Collect(ch chan<- prometheus.Metric) {
	stats := m.tunnels.Stats()

	// Active tunnels (total)
	activeTunnels, _ := stats["active_tunnels"].(int)
	ch <- prometheus.MustNewConstMetric(m.activeTunnels, prometheus.GaugeValue, float64(activeTunnels))

	// Tunnels by protocol
	if byProto, ok := stats["by_protocol"].(map[string]int); ok {
		for proto, count := range byProto {
			ch <- prometheus.MustNewConstMetric(m.tunnelsByProto, prometheus.GaugeValue, float64(count), proto)
		}
	}

	// Active relays
	ch <- prometheus.MustNewConstMetric(m.activeRelays, prometheus.GaugeValue, float64(m.relays.Count()))

	// Bytes counters
	bytesSent, _ := stats["bytes_sent"].(int64)
	bytesRecv, _ := stats["bytes_received"].(int64)
	ch <- prometheus.MustNewConstMetric(m.bytesSentTotal, prometheus.CounterValue, float64(bytesSent))
	ch <- prometheus.MustNewConstMetric(m.bytesRecvTotal, prometheus.CounterValue, float64(bytesRecv))

	// Draining flag
	var drainingVal float64
	if m.isDraining.Load() {
		drainingVal = 1
	}
	ch <- prometheus.MustNewConstMetric(m.draining, prometheus.GaugeValue, drainingVal)

	// Non-migratable tunnel count
	ch <- prometheus.MustNewConstMetric(m.nonMigratableTun, prometheus.GaugeValue, float64(m.tunnels.NonMigratableCount()))
}

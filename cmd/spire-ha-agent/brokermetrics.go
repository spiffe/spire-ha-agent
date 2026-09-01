package main

import (
	"log"
	"net"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics live on a private registry rather than prometheus.DefaultRegisterer
// (which cmd/spire-trust-sync uses). Tests boot several brokerMain instances
// in one process and their goroutines never exit, so package-level gauges on
// the shared default registry would stomp each other's values.
type brokerMetrics struct {
	registry *prometheus.Registry
	// 1 when that side's named global bundle subscription is established.
	upstreamUp *prometheus.GaugeVec
	// 1 when every one of that side's subscriptions is established. Exists so
	// alerting can be a bare `== 0` rather than a PromQL aggregation.
	upstreamSideUp *prometheus.GaugeVec
}

func newBrokerMetrics() *brokerMetrics {
	m := &brokerMetrics{
		registry: prometheus.NewRegistry(),
		upstreamUp: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "spire_ha_agent_upstream_up",
			Help: "Whether an upstream side's bundle subscription is currently established (1 = up, 0 = down).",
		}, []string{"side", "stream"}),
		upstreamSideUp: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "spire_ha_agent_upstream_side_up",
			Help: "Whether all of an upstream side's bundle subscriptions are currently established (1 = up, 0 = down).",
		}, []string{"side"}),
	}
	m.registry.MustRegister(m.upstreamUp, m.upstreamSideUp)
	m.registry.MustRegister(collectors.NewGoCollector())
	m.registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m
}

// Creates every series at 0 so a scraper sees an explicit down rather than a
// missing series before the first subscription is attempted.
func (m *brokerMetrics) init(multi bool) {
	sides := []string{"a"}
	if multi {
		sides = append(sides, "b")
	}
	for _, side := range sides {
		m.upstreamSideUp.WithLabelValues(side).Set(0)
		for _, stream := range []string{"x509", "jwt"} {
			m.upstreamUp.WithLabelValues(side, stream).Set(0)
		}
	}
}

func (m *brokerMetrics) serve(addr string) {
	// Own mux, not http.DefaultServeMux, for the same isolation reason as the
	// private registry.
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{}))
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("metrics: failed to listen on %s: %v", addr, err)
	}
	log.Printf("metrics listening on http://%s/metrics", addr)
	go func() {
		log.Fatalf("metrics server failed: %v", http.Serve(lis, mux))
	}()
}

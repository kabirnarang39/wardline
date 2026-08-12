package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// PrometheusRecorder is the real Recorder, backed by its own private
// registry rather than prometheus.DefaultRegisterer -- more than one
// wardline instance in the same process (table-driven tests, a future
// second NewPrometheus call) would otherwise panic on duplicate metric
// registration against the global default.
type PrometheusRecorder struct {
	registry        *prometheus.Registry
	requestsTotal   *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
}

// NewPrometheus builds a PrometheusRecorder. It also registers Go runtime
// (goroutines, heap, GC) and process (open FDs, RSS) collectors on the same
// registry -- the exact signals the soak-test runbook entry watches via
// pprof/runtime stats today, now scrapeable without attaching a debugger.
func NewPrometheus() *PrometheusRecorder {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	return &PrometheusRecorder{
		registry: reg,
		requestsTotal: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Namespace: "wardline",
			Name:      "proxy_requests_total",
			Help:      "Total proxied tool calls, by decision.",
		}, []string{"decision"}),
		requestDuration: promauto.With(reg).NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "wardline",
			Name:      "proxy_request_duration_seconds",
			Help:      "Proxied tool call latency in seconds, by decision.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"decision"}),
	}
}

func (r *PrometheusRecorder) ObserveRequest(decision string, duration time.Duration) {
	r.requestsTotal.WithLabelValues(decision).Inc()
	r.requestDuration.WithLabelValues(decision).Observe(duration.Seconds())
}

// Handler serves this recorder's registry in the Prometheus text exposition
// format -- mount at GET /metrics only when features.prometheus_metrics is
// on (see cmd/wardline/main.go).
func (r *PrometheusRecorder) Handler() http.Handler {
	return promhttp.HandlerFor(r.registry, promhttp.HandlerOpts{})
}

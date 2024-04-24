package metricssupport

// TODO: this code came from policy-orchestrator... does not seem complete

import (
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type metricsHandler struct {
}

func (h metricsHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("{}"))
}

func MetricsHandler() http.Handler {
	return metricsHandler{}
}

var (
	httpDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "hexaAuthZen_http_duration_seconds",
		Help: "Duration of HTTP requests.",
	}, []string{"path"})
)

func PrometheusHttpMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// log.Println("*** GoSignals Prometheus handler called!!")
		route := mux.CurrentRoute(r)
		path, _ := route.GetPathTemplate()
		timer := prometheus.NewTimer(httpDuration.WithLabelValues(path))
		next.ServeHTTP(w, r)
		timer.ObserveDuration()
	})
}

func MetricsMiddleware(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, s := range []string{"/styles", "/images"} {
			if strings.HasPrefix(r.URL.Path, s) {
				next.ServeHTTP(w, r)
				return
			}
		}
		// route := mux.CurrentRoute(r)
		// path, _ := route.GetPathTemplate()
		// config.ServerLog.Printf("Returning metrics: %v\n", path)
		next.ServeHTTP(w, r)
	})
}

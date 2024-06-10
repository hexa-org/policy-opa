package websupport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"

	log "golang.org/x/exp/slog"

	"github.com/gorilla/mux"
	"github.com/hexa-org/policy-opa/pkg/healthsupport"
	"github.com/hexa-org/policy-opa/pkg/metricssupport"
)

type Options struct {
	HealthChecks []healthsupport.HealthCheck
}

type Path struct {
	URI     string
	Methods []string
}

func Paths(router *mux.Router) []Path {
	var paths []Path
	_ = router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		uri, _ := route.GetPathTemplate()
		methods, _ := route.GetMethods()
		paths = append(paths, Path{uri, methods})
		return nil
	})
	return paths
}

func Create(addr string, handlers func(x *mux.Router), options Options) *http.Server {
	checks := options.HealthChecks
	if checks == nil || len(checks) == 0 {
		checks = append(checks, &healthsupport.NoopCheck{})
	}

	router := mux.NewRouter()
	router.Use(metricssupport.MetricsMiddleware)
	router.HandleFunc("/health",
		func(w http.ResponseWriter, r *http.Request) {
			healthsupport.HealthHandlerFunctionWithChecks(w, r, checks)
		},
	).Methods("GET")
	router.Path("/metrics").Handler(metricssupport.MetricsHandler())
	router.StrictSlash(true)
	handlers(router)
	server := http.Server{
		Addr:    addr,
		Handler: router,
	}
	for _, p := range Paths(router) {
		log.Info("Registered route", "methods", p.Methods, "path", p.URI)
	}
	return &server
}

func Start(server *http.Server, l net.Listener) {
	if server.TLSConfig != nil {
		log.Info("Starting with TLS", "address", server.Addr)
		err := server.ServeTLS(l, "", "")
		if !errors.Is(err, http.ErrServerClosed) {
			log.Error(fmt.Sprintf("error starting the server: %s", err.Error()))
			return
		}
		return
	}

	log.Info("Starting the server", "address", server.Addr)
	log.Warn("TLS server mode not configured")
	err := server.Serve(l)
	if err != nil {
		if !errors.Is(err, http.ErrServerClosed) {
			log.Error(fmt.Sprintf("error starting the server: %s", err.Error()))
		}
		return
	}
}

func Stop(server *http.Server) {
	log.Info("Stopping the server.")
	_ = server.Shutdown(context.Background())
}

func WithTransportLayerSecurity(certFile, keyFile string, app *http.Server) {
	cert, certErr := os.ReadFile(certFile)
	if certErr != nil {
		panic(certErr.Error())
	}
	key, keyErr := os.ReadFile(keyFile)
	if keyErr != nil {
		panic(certErr.Error())
	}
	pair, pairErr := tls.X509KeyPair(cert, key)
	if pairErr != nil {
		panic(pairErr.Error())
	}
	app.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{pair},
	}
}

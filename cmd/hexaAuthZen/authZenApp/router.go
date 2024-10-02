package authZenApp

import (
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/hexa-org/policy-mapper/pkg/healthsupport"
	"github.com/hexa-org/policy-mapper/pkg/metricssupport"
	"github.com/hexa-org/policy-mapper/pkg/oauth2support"
	"github.com/hexa-org/policy-mapper/pkg/tokensupport"
	"github.com/hexa-org/policy-mapper/pkg/websupport"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/config"
)

type Route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
	IsIdQuery   bool
}

type HttpRouter struct {
	router *mux.Router
	az     *AuthZenApp
}

type Routes []Route

func NewRouter(application *AuthZenApp) *HttpRouter {
	httpRouter := HttpRouter{
		router: mux.NewRouter().StrictSlash(true),
		az:     application,
	}

	// Add the Prometheus middleware first so logging happens inside
	httpRouter.router.Use(metricssupport.PrometheusHttpMiddleware)

	// httpRouter.router.Use()
	routes := httpRouter.getRoutes()

	for _, route := range routes {
		var handler http.Handler
		handler = route.HandlerFunc
		handler = application.Logger(handler, route.Name)
		/*
			if route.IsIdQuery {
				httpRouter.router.
					Methods(route.Method).
					Path(route.Pattern).
					Name(route.Name).
					Handler(handler).
					Evaluations("id", "{id:[a-fA-F0-9]+}")
			}
			else {
		*/
		httpRouter.router.
			Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(handler)

	}

	// Add prometheus handler at metrics endpoint
	options := websupport.Options{}
	checks := options.HealthChecks
	if checks == nil || len(checks) == 0 {
		checks = append(checks, &AuthZenHealthCheck{App: application})
	}

	router := httpRouter.router
	router.Use(metricssupport.MetricsMiddleware)
	router.HandleFunc("/health",
		func(w http.ResponseWriter, r *http.Request) {
			healthsupport.HealthHandlerFunctionWithChecks(w, r, checks)
		},
	).Methods("GET")
	router.Path("/metrics").Handler(metricssupport.MetricsHandler())

	return &httpRouter
}

type AuthZenHealthCheck struct {
	App *AuthZenApp
}

type HealthInfo struct {
	Status string `json:"status"`
}

func (h *AuthZenHealthCheck) Name() string { return "HexaAuthZen" }

func (h *AuthZenHealthCheck) Check() bool {
	return h.App.Decision != nil && h.App.Decision.HealthCheck()
}

func (h *HttpRouter) getRoutes() Routes {
	// TODO what is mode?

	tokenAuth := h.az.TokenAuthorizer
	var scopeBundle, scopeDecision []string

	var routes []Route
	mode := os.Getenv(tokensupport.EnvTknEnforceMode)
	switch mode {
	case tokensupport.ModeEnforceBundle:
		scopeBundle = []string{tokensupport.ScopeBundle, tokensupport.ScopeAdmin}
		routes = Routes{
			Route{
				"Index",
				"GET",
				"/",
				h.az.Index,
				false,
			},
			Route{
				"Evaluation",
				"POST",
				config.EndpointAuthzenSingleDecision,
				h.az.HandleEvaluation,
				false,
			},
			Route{
				"Query Evaluation",
				"POST",
				config.EndpointAuthzenQuery,
				h.az.HandleQueryEvaluation,
				false,
			},
			Route{
				"Update Bundle",
				"POST",
				config.EndpointOpaBundles,
				oauth2support.JwtAuthenticationHandler(h.az.BundleUpload, tokenAuth, scopeBundle),
				false,
			},
			Route{
				Name:        "Get Bundle",
				Method:      "GET",
				Pattern:     config.EndpointGetOpaBundles,
				HandlerFunc: oauth2support.JwtAuthenticationHandler(h.az.BundleDownload, tokenAuth, scopeBundle),
				IsIdQuery:   false,
			},
		}
	case tokensupport.ModeEnforceAll:
		scopeBundle = []string{tokensupport.ScopeBundle, tokensupport.ScopeAdmin}
		scopeDecision = []string{tokensupport.ScopeDecision, tokensupport.ScopeAdmin}
		routes = Routes{
			Route{
				"Index",
				"GET",
				"/",
				h.az.Index,
				false,
			},
			Route{
				"Evaluation",
				"POST",
				config.EndpointAuthzenSingleDecision,
				oauth2support.JwtAuthenticationHandler(h.az.HandleEvaluation, tokenAuth, scopeDecision),
				false,
			},
			Route{
				"Query Evaluation",
				"POST",
				config.EndpointAuthzenQuery,
				oauth2support.JwtAuthenticationHandler(h.az.HandleQueryEvaluation, tokenAuth, scopeDecision),
				false,
			},
			Route{
				"Update Bundle",
				"POST",
				config.EndpointOpaBundles,
				oauth2support.JwtAuthenticationHandler(h.az.BundleUpload, tokenAuth, scopeBundle),
				false,
			},
			Route{
				Name:        "Get Bundle",
				Method:      "GET",
				Pattern:     config.EndpointGetOpaBundles,
				HandlerFunc: oauth2support.JwtAuthenticationHandler(h.az.BundleDownload, tokenAuth, scopeBundle),
				IsIdQuery:   false,
			},
		}
	default:
		scopeBundle = nil
		scopeDecision = nil
		routes = Routes{
			Route{
				"Index",
				"GET",
				"/",
				h.az.Index,
				false,
			},
			Route{
				"Evaluation",
				"POST",
				config.EndpointAuthzenSingleDecision,
				h.az.HandleEvaluation,
				false,
			},
			Route{
				"Query Evaluation",
				"POST",
				config.EndpointAuthzenQuery,
				h.az.HandleQueryEvaluation,
				false,
			},
			Route{
				"Update Bundle",
				"POST",
				config.EndpointOpaBundles,
				h.az.BundleUpload,
				false,
			},
			Route{
				Name:        "Get Bundle",
				Method:      "GET",
				Pattern:     config.EndpointGetOpaBundles,
				HandlerFunc: h.az.BundleDownload,
				IsIdQuery:   false,
			},
		}
	}

	return routes
}

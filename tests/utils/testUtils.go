package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	opaTools "github.com/hexa-org/policy-opa/client/opa"
)

/*
This is a mock server that simply returns the http request infor as an OPA input structure to the requesting client.
Main purpose is to test how OpaInput works against http.Request
*/
func GetUpMockServer(key string, path string) *http.Server {
	err := os.Setenv("OPATOOLS_JWTVERIFYKEY", key)
	if err != nil {
		log.Fatalln(err)
	}
	if path == "" {
		path = "/testpath"
	}
	listener, _ := net.Listen("tcp", "localhost:0")

	// Need to fix this so it will just serve anything for policy testing
	server := CreateServer(listener.Addr().String(), func(router *mux.Router) {
		router.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			input := opaTools.PrepareInput(r)
			marshal, _ := json.Marshal(input)
			_, _ = w.Write(marshal)
		}).Queries("a", "{a}", "c", "{c}")
	}, Options{})

	go StartServer(server, listener)

	WaitForHealthy(server)
	return server
}

func GenerateBearerToken(key string, subject string, expires time.Time) (string, error) {
	claims := &opaTools.HexaClaims{
		&jwt.RegisteredClaims{
			Issuer:    "testIssuer",
			Audience:  []string{"testAudience"},
			ExpiresAt: &jwt.NumericDate{expires},
			Subject:   subject,
		},
		"bearer abc",
	}

	t := jwt.New(jwt.GetSigningMethod("HS256"))
	t.Claims = claims
	return t.SignedString([]byte(key))
}

type httpClient interface {
	Get(url string) (*http.Response, error)
}

func WaitForHealthy(server *http.Server) {
	WaitForHealthyWithClient(server, http.DefaultClient, fmt.Sprintf("http://%s/health", server.Addr))
}

func WaitForHealthyWithClient(server *http.Server, client httpClient, url string) {
	var isLive bool
	for !isLive {
		resp, err := client.Get(url)
		if err == nil && resp.StatusCode == http.StatusOK {
			log.Println("Server is healthy.", server.Addr)
			isLive = true
		}
	}
}

type NoopCheck struct {
}

func (d *NoopCheck) Name() string {
	return "noop"
}

func (d *NoopCheck) Check() bool {
	return true
}

type HealthCheck interface {
	Name() string
	Check() bool
}

type Options struct {
	HealthChecks []HealthCheck
}

type response struct {
	Name string `json:"name"`
	Pass string `json:"pass"`
}

func HealthHandlerFunctionWithChecks(w http.ResponseWriter, _ *http.Request, checks []HealthCheck) {
	responses := make([]response, 0)
	for _, check := range checks {
		responses = append(responses, response{
			Name: check.Name(),
			Pass: strconv.FormatBool(check.Check()),
		})
	}
	data, _ := json.Marshal(responses)
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
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

func CreateServer(addr string, handlers func(x *mux.Router), options Options) *http.Server {
	checks := options.HealthChecks
	if checks == nil || len(checks) == 0 {
		checks = append(checks, &NoopCheck{})
	}

	router := mux.NewRouter()
	// router.Use(metricssupport.MetricsMiddleware)
	router.HandleFunc("/health",
		func(w http.ResponseWriter, r *http.Request) {
			HealthHandlerFunctionWithChecks(w, r, checks)
		},
	).Methods("GET")
	// router.Path("/metrics").Handler(metricssupport.MetricsHandler())
	router.StrictSlash(true)
	handlers(router)
	server := http.Server{
		Addr:    addr,
		Handler: router,
	}
	for _, p := range Paths(router) {
		log.Println("Registered route", p.Methods, p.URI)
	}
	return &server
}

func StartServer(server *http.Server, l net.Listener) {
	if server.TLSConfig != nil {
		log.Println("Starting the server with tls support", server.Addr)
		err := server.ServeTLS(l, "", "")
		if err != nil {
			log.Println("error starting the server:", err.Error())
			return
		}
	}

	log.Println("Starting the server", server.Addr)
	err := server.Serve(l)
	if err != nil {
		log.Println("error starting the server:", err.Error())
		return
	}
}

func StopServer(server *http.Server) {
	log.Printf("Stopping the server.")
	_ = server.Shutdown(context.Background())
}

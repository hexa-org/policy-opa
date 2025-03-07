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
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	opaTools "github.com/hexa-org/policy-opa/client/hexaOpaClient"
)

/*
SetUpMockServer is a mock server that simply returns the http request infor as an OPA input structure to the requesting client.
The main purpose of this utility to test how OpaInput works against http.Request
*/
func SetUpMockServer(key string, path string, mockOidcMode bool, t *testing.T) *http.Server {
	t.Helper()
	err := os.Setenv("OPATOOLS_JWTVERIFYKEY", key)
	if err != nil {
		log.Fatalln(err)
	}
	if path == "" {
		path = "/testpath"
	}
	listener, _ := net.Listen("tcp", "localhost:0")

	// Need to fix this so it will just serve anything for policy testing
	server := CreateServer(t, listener.Addr().String(), func(router *mux.Router) {
		router.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			var input *opaTools.OpaInfo
			if mockOidcMode {
				input = opaTools.PrepareInputWithClaimsFunc(r, func() *jwt.MapClaims {
					claims := jwt.MapClaims{}
					input = opaTools.PrepareInput(r, []string{}, []string{"CanaryProfileService"})

					claims["sub"] = input.Subject.Sub
					claims["iss"] = input.Subject.Issuer
					claims["aud"] = input.Subject.Audience
					claims["iat"] = float64(input.Subject.IssuedAt.Unix())
					claims["exp"] = float64(input.Subject.Expires.Unix())
					claims["nbf"] = float64(input.Subject.NotBefore.Unix())
					claims["email"] = input.Subject.Sub
					roles := make([]interface{}, 2)
					roles[0] = "a"
					roles[1] = "b"
					claims["roles"] = roles
					return &claims
				}, []string{}, []string{"CanaryProfileService"})
			} else {
				input = opaTools.PrepareInput(r, []string{}, []string{"CanaryProfileService"})
			}
			marshal, _ := json.Marshal(input)
			_, _ = w.Write(marshal)
		}).Queries("a", "{a}", "c", "{c}")
	}, Options{})

	go StartServer(t, server, listener)

	WaitForHealthy(server)
	return server
}

func GenerateBearerToken(key string, subject string, expires time.Time) (string, error) {
	now := time.Now()
	claims := &opaTools.HexaClaims{
		RegisteredClaims: &jwt.RegisteredClaims{
			Issuer:    "testIssuer",
			Audience:  []string{"testAudience"},
			ExpiresAt: &jwt.NumericDate{Time: expires},
			Subject:   subject,
			NotBefore: &jwt.NumericDate{Time: now},
			IssuedAt:  &jwt.NumericDate{Time: now},
		},
		Roles: "bearer abc",
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

func CreateServer(t *testing.T, addr string, handlers func(x *mux.Router), options Options) *http.Server {
	t.Helper()
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

func StartServer(t *testing.T, server *http.Server, l net.Listener) {
	t.Helper()
	if server.TLSConfig != nil {
		t.Log("Starting the server with tls support", server.Addr)
		err := server.ServeTLS(l, "", "")
		if err != nil {
			log.Println("error starting the server:", err.Error())
			return
		}
	}

	log.Println("Starting the server", server.Addr)
	err := server.Serve(l)
	if err != nil {
		if err != http.ErrServerClosed {
			t.Error("error starting the server:", err.Error())
		}
		return
	}
}

func StopServer(t *testing.T, server *http.Server) {
	t.Helper()
	log.Println("Stopping the server.")
	_ = server.Shutdown(context.Background())
}

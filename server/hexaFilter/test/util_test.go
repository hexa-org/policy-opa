package test_test

import (
	"encoding/json"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	opaTools "github.com/hexa-org/policy-opa/client/opa"
	"github.com/hexa-org/policy-orchestrator/pkg/healthsupport"

	"github.com/hexa-org/policy-orchestrator/pkg/websupport"
	"log"
	"net"
	"net/http"
	"os"
	"time"
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
	server := websupport.Create(listener.Addr().String(), func(router *mux.Router) {
		router.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			input := opaTools.PrepareInput(r)
			marshal, _ := json.Marshal(input)
			_, _ = w.Write(marshal)
		}).Queries("a", "{a}", "c", "{c}")
	}, websupport.Options{})

	go websupport.Start(server, listener)

	healthsupport.WaitForHealthy(server)
	return server
}

func GenerateBearerToken(key string, subject string, expires time.Time) (string, error) {
	claims := &opaTools.HexaClaims{
		&jwt.StandardClaims{
			Issuer:    "testIssuer",
			Audience:  "testAudience",
			ExpiresAt: expires.Unix(),
			Subject:   subject,
		},
		"bearer abc",
	}

	t := jwt.New(jwt.GetSigningMethod("HS256"))
	t.Claims = claims
	return t.SignedString([]byte(key))
}

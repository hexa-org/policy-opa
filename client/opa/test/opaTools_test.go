package test_test

import (
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	opaTools "github.com/hexa-org/policy-mapper/client/opa"
	"github.com/hexa-org/policy-orchestrator/pkg/healthsupport"

	"github.com/hexa-org/policy-orchestrator/pkg/websupport"
	"github.com/stretchr/testify/assert"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAnonymous(t *testing.T) {

	server := GetUpMockServer("verifymenow", "")

	resp, err := http.Get(fmt.Sprintf("http://%s/testpath?a=b&c=d", server.Addr))
	if err != nil {
		log.Fatalln(err)
	}
	body, _ := io.ReadAll(resp.Body)

	var input opaTools.OpaInfo
	err = json.Unmarshal(body, &input)
	assert.NoError(t, err)
	fmt.Println(string(body))
	reqInfo := input.Req

	assert.NotNil(t, reqInfo)
	assert.True(t, strings.HasPrefix(reqInfo.ClientIp, "127.0.0.1:"))
	reqTime := reqInfo.Time
	assert.True(t, reqTime.Before(time.Now()))

	subInfo := input.Subject
	assert.Equal(t, "Anonymous", subInfo.Type)
	assert.Equal(t, 2, len(reqInfo.Header))
	websupport.Stop(server)
}

func TestBasicAuth(t *testing.T) {

	server := GetUpMockServer("verifyme", "")

	client := &http.Client{Timeout: time.Second * 10}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/testpath?a=b&c=d", server.Addr), nil)
	if err != nil {
		assert.Error(t, err)
	}
	req.SetBasicAuth("testUser", "good&bad")
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	body, _ := io.ReadAll(resp.Body)

	var input opaTools.OpaInfo
	err = json.Unmarshal(body, &input)
	assert.NoError(t, err)
	reqInfo := input.Req
	fmt.Println(string(body))
	assert.True(t, strings.HasPrefix(reqInfo.ClientIp, "127.0.0.1:"))

	assert.NotNil(t, reqInfo)
	assert.NotNil(t, reqInfo.ClientIp)
	reqTime := reqInfo.Time
	assert.True(t, reqTime.Before(time.Now()))

	subInfo := input.Subject
	assert.Equal(t, subInfo.Type, "basic")
	assert.Equal(t, subInfo.Sub, "testUser")
	websupport.Stop(server)
}

func TestJwtAuth(t *testing.T) {
	key := "sercrethatmaycontainch@r$32chars!"
	server := GetUpMockServer(key, "")

	client := &http.Client{Timeout: time.Minute * 2}

	toknstr, err := GenerateBearerToken(key, "TestUser", time.Now().Add(time.Minute*1))
	if err != nil {
		log.Fatalln(err)
	}
	authz := "Bearer " + toknstr
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/testpath?a=b&c=d", server.Addr), nil)
	if err != nil {
		assert.Error(t, err)
	}
	req.Header.Set("Authorization", authz)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	body, _ := io.ReadAll(resp.Body)

	var input opaTools.OpaInfo
	err = json.Unmarshal(body, &input)
	assert.NoError(t, err)
	reqInfo := input.Req
	subInfo := input.Subject

	fmt.Println(string(body))
	assert.True(t, strings.HasPrefix(reqInfo.ClientIp, "127.0.0.1:"))

	assert.NotNil(t, reqInfo)
	assert.NotNil(t, reqInfo.ClientIp)
	reqTime := reqInfo.Time
	assert.True(t, reqTime.Before(time.Now()))
	assert.Equal(t, 3, len(reqInfo.Header))

	assert.Equal(t, "Bearer+JWT", subInfo.Type)
	assert.Equal(t, "TestUser", subInfo.Sub)

	websupport.Stop(server)
}

func TestExpiredJwtAuth(t *testing.T) {
	key := "sercrethatmaycontainch@r$32chars!"
	server := GetUpMockServer(key, "")

	client := &http.Client{Timeout: time.Minute * 2}

	oldDate := time.Date(2020, 1, 1, 12, 00, 0, 0, time.UTC)
	toknstr, err := GenerateBearerToken(key, "TestUser", oldDate)
	if err != nil {
		log.Fatalln(err)
	}
	authz := "Bearer " + toknstr
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/testpath?a=b&c=d", server.Addr), nil)
	if err != nil {
		assert.Error(t, err)
	}
	req.Header.Set("Authorization", authz)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	body, _ := io.ReadAll(resp.Body)

	var input opaTools.OpaInfo
	err = json.Unmarshal(body, &input)
	assert.NoError(t, err)

	subInfo := input.Subject

	fmt.Println(string(body))
	assert.True(t, strings.HasPrefix(subInfo.Type, "Invalid"))

	websupport.Stop(server)
}

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

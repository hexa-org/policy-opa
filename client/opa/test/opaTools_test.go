package test

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hexa-org/policy-opa/client/opa"
	"github.com/hexa-org/policy-opa/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestAnonymous(t *testing.T) {

	server := utils.GetUpMockServer("verifymenow", "")

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
	utils.StopServer(server)
}

func TestBasicAuth(t *testing.T) {

	server := utils.GetUpMockServer("verifyme", "")

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
	utils.StopServer(server)
}

func TestJwtAuth(t *testing.T) {
	key := "sercrethatmaycontainch@r$32chars!"
	server := utils.GetUpMockServer(key, "")

	client := &http.Client{Timeout: time.Minute * 2}

	toknstr, err := utils.GenerateBearerToken(key, "TestUser", time.Now().Add(time.Minute*2))
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

	utils.StopServer(server)
}

func TestExpiredJwtAuth(t *testing.T) {
	key := "sercrethatmaycontainch@r$32chars!"
	server := utils.GetUpMockServer(key, "")

	client := &http.Client{Timeout: time.Minute * 2}

	oldDate := time.Date(2020, 1, 1, 12, 00, 0, 0, time.UTC)
	toknstr, err := utils.GenerateBearerToken(key, "TestUser", oldDate)
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

	utils.StopServer(server)
}

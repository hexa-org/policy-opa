package authZenApp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/hexa-org/policy-opa/api/infoModel"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/config"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/userHandler"
	"github.com/hexa-org/policy-opa/pkg/bundleTestSupport"
	"github.com/hexa-org/policy-opa/pkg/compressionsupport"
	"github.com/hexa-org/policy-opa/pkg/healthsupport"
	"github.com/hexa-org/policy-opa/pkg/tokensupport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type testSuite struct {
	suite.Suite
	app          *AuthZenApp
	log          *log.Logger
	addr         string
	bundleDir    string
	tokenDir     string
	tokenHandler *tokensupport.TokenHandler
	bundleAuth   string
	azAuth       string
}

func TestAuthZenApp(t *testing.T) {

	s := testSuite{}
	s.bundleDir = bundleTestSupport.InitTestBundlesDir(nil)

	suite.Run(t, &s)

	bundleTestSupport.Cleanup(s.tokenDir)
	bundleTestSupport.Cleanup(s.bundleDir)
}

func (s *testSuite) setUpTokenSystem() {
	tempdir, err := os.MkdirTemp("", "authzenToken-*")
	assert.NoError(s.T(), err, "No error creating temp directory for tokens")
	s.tokenDir = tempdir
	_ = os.Setenv(tokensupport.EnvTknKeyDirectory, tempdir)
	_ = os.Unsetenv(tokensupport.EnvTknPubKeyFile)
	_ = os.Unsetenv(tokensupport.EnvTknPrivateKeyFile)

	s.tokenHandler, err = tokensupport.GenerateIssuerKeys("authzen", false)
	assert.NoError(s.T(), err, "Check no error generating issuer")
	assert.Equal(s.T(), "authzen", s.tokenHandler.TokenIssuer, "Check issuer set")

	s.bundleAuth, err = s.tokenHandler.IssueToken([]string{tokensupport.ScopeBundle}, "bundle@hexa.org")
	s.azAuth, err = s.tokenHandler.IssueToken([]string{tokensupport.ScopeDecision}, "az@hexa.org")

}

func (s *testSuite) SetupSuite() {
	s.log = config.ServerLog
	fmt.Println("Initializing token system...")
	s.setUpTokenSystem()

	fmt.Println("Starting Authzen server...")
	_ = os.Setenv(config.EnvBundleDir, s.bundleDir)
	_ = os.Setenv(config.EnvAuthUserPipFile, userHandler.DefaultUserPipFile)
	_ = os.Setenv(tokensupport.EnvTknEnforceMode, tokensupport.ModeEnforceAll) // tokens not needed for testings
	listener, _ := net.Listen("tcp", "localhost:0")
	s.addr = listener.Addr().String()
	s.app = StartServer(s.addr, "")
	go func() {
		_ = s.app.Server.Serve(listener)
	}()

	healthsupport.WaitForHealthy(s.app.Server)
}

func (s *testSuite) TearDownSuite() {
	_ = os.Unsetenv(tokensupport.EnvTknEnforceMode)
	_ = os.Unsetenv(config.EnvBundleDir)
	_ = os.Unsetenv(config.EnvAuthUserPipFile)
	_ = os.Unsetenv(tokensupport.EnvTknKeyDirectory)
	_ = os.Unsetenv(tokensupport.EnvTknPubKeyFile)
	_ = os.Unsetenv(tokensupport.EnvTknPrivateKeyFile)

	s.app.Shutdown()

}

func (s *testSuite) TestAuthorizationEndpoint() {
	fmt.Println("Testing authorization")

	bodyStruct := infoModel.AuthRequest{
		Subject: infoModel.SubjectInfo{Identity: "CiRmZDM2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"},
		Action:  infoModel.ActionInfo{Name: "can_read_todos"},
	}

	bodyBytes, err := json.Marshal(&bodyStruct)
	assert.NoError(s.T(), err, "Check no error serializing request")

	reqUrl := url.URL{
		Scheme: "http",
		Host:   s.addr,
		Path:   config.EndpointAuthzenSingleDecision,
	}

	fmt.Println("Testing unauthorized...")
	assert.Nil(s.T(), err, "Should be no error generating url")
	req, err := http.NewRequest("POST", reqUrl.String(), bytes.NewReader(bodyBytes))
	assert.NotNil(s.T(), req)
	req.Header.Set(config.HeaderRequestId, "1234")

	client := http.Client{}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	assert.Nil(s.T(), err, "Should be no error making request")

	assert.Equal(s.T(), http.StatusUnauthorized, resp.StatusCode, "Should be unauthorized")

	bodyBytes, err = io.ReadAll(resp.Body)
	assert.NoError(s.T(), err, "Check error reading body on unauthorized requests")
	assert.Empty(s.T(), bodyBytes, "Check no body in response")

	reqId := resp.Header.Get(config.HeaderRequestId)
	assert.Equal(s.T(), "1234", reqId, "Request id should be 1234")

	fmt.Println("Testing forbidden...")

	req.Header.Set("Authorization", "Bearer "+s.bundleAuth)
	req.Header.Set(config.HeaderRequestId, "5678")

	resp, err = client.Do(req)
	assert.Nil(s.T(), err, "Should be no error making request")

	assert.Equal(s.T(), http.StatusForbidden, resp.StatusCode, "Should be forbidden")

	bodyBytes, err = io.ReadAll(resp.Body)
	assert.NoError(s.T(), err, "Check error reading body on forbidden request")
	assert.Empty(s.T(), bodyBytes, "Check no body in response")

	reqId = resp.Header.Get(config.HeaderRequestId)
	assert.Equal(s.T(), "5678", reqId, "Request id should be 1234")

	fmt.Println("Testing authorization...")
	req.Header.Set("Authorization", "Bearer "+s.azAuth)
	req.Header.Set(config.HeaderRequestId, "90")
	resp, err = client.Do(req)
	assert.Nil(s.T(), err, "Should be no error making request")

	assert.Equal(s.T(), http.StatusOK, resp.StatusCode, "Should be status ok")

	respBody, err := io.ReadAll(resp.Body)
	assert.Nil(s.T(), err, "Should be no error reading response body")

	var simpleResponse infoModel.SimpleResponse
	err = json.Unmarshal(respBody, &simpleResponse)
	assert.NoError(s.T(), err, "response was parsed")
	assert.True(s.T(), simpleResponse.Decision, "check decision is true")
}

func (s *testSuite) TestGetBundle() {
	fmt.Println("Testing GetBundle")

	reqUrl := url.URL{
		Scheme: "http",
		Host:   s.addr,
		Path:   config.EndpointGetOpaBundles,
	}

	req, err := http.NewRequest(http.MethodGet, reqUrl.String(), nil)
	req.Header.Set("Authorization", "Bearer "+s.bundleAuth)
	assert.NoError(s.T(), err, "No error creating request")

	client := http.Client{}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	assert.Nil(s.T(), err, "Should be no error making request")
	assert.Equal(s.T(), http.StatusOK, resp.StatusCode, " Should be status Ok")

	tempDir, err := os.MkdirTemp("", "authzen-*")
	assert.NoError(s.T(), err, "No error creating tempdir")
	defer bundleTestSupport.Cleanup(tempDir)

	gzip, err := compressionsupport.UnGzip(resp.Body)
	assert.NoError(s.T(), err, "Body was unzipped")

	err = compressionsupport.UnTarToPath(bytes.NewReader(gzip), tempDir)

	_, err = os.Stat(filepath.Join(tempDir, "bundle", "hexaPolicy.rego"))
	assert.NoError(s.T(), err, "Rego should be there")

	_, err = os.Stat(filepath.Join(tempDir, "bundle", "data.json"))
	assert.NoError(s.T(), err, "Rego should be there")
}

func (s *testSuite) TestHealth() {
	fmt.Println("Testing Health")
	reqUrl := url.URL{
		Scheme: "http",
		Host:   s.addr,
		Path:   "/health",
	}

	req, _ := http.NewRequest(http.MethodGet, reqUrl.String(), nil)

	client := http.Client{}
	defer client.CloseIdleConnections()

	resp, err := client.Do(req)
	assert.Nil(s.T(), err, "No error on health request")
	assert.Equal(s.T(), http.StatusOK, resp.StatusCode, "Status 200 response")

	bodyBytes, err := io.ReadAll(resp.Body)
	status := string(bodyBytes)
	assert.Contains(s.T(), status, "{\"name\":\"HexaAuthZen\",\"pass\":\"true\"}", "Correct response verified")
	fmt.Println("Response:")
	fmt.Println(string(status))

}

func (s *testSuite) TestMetrics() {
	fmt.Println("Testing Metrics")
	reqUrl := url.URL{
		Scheme: "http",
		Host:   s.addr,
		Path:   "/metrics",
	}

	req, _ := http.NewRequest(http.MethodGet, reqUrl.String(), nil)

	client := http.Client{}
	defer client.CloseIdleConnections()

	resp, err := client.Do(req)
	assert.Nil(s.T(), err, "No error on metrics request")
	assert.Equal(s.T(), http.StatusOK, resp.StatusCode, "Status 200 response")

	bodyBytes, err := io.ReadAll(resp.Body)
	status := string(bodyBytes)
	// assert.Contains(s.T(), status, "{\"name\":\"HexaAuthZen\",\"pass\":\"true\"}", "Correct response verified")
	fmt.Println("Response:")
	fmt.Println(string(status))
}

func (s *testSuite) TestIndex() {
	fmt.Println("Testing Index")
	reqUrl := url.URL{
		Scheme: "http",
		Host:   s.addr,
		Path:   "/",
	}

	req, _ := http.NewRequest(http.MethodGet, reqUrl.String(), nil)

	client := http.Client{}
	defer client.CloseIdleConnections()

	resp, err := client.Do(req)
	assert.Nil(s.T(), err, "No error on metrics request")
	assert.Equal(s.T(), http.StatusOK, resp.StatusCode, "Status 200 response")

	bodyBytes, err := io.ReadAll(resp.Body)
	status := string(bodyBytes)
	assert.Contains(s.T(), status, "Hexa Authzen Test Server", "Correct response verified")
	fmt.Println("Response:")
	fmt.Println(string(status))
}

func (s *testSuite) TestLogger() {
	var buf bytes.Buffer
	origLog := httpLog

	httpLog = log.New(&buf, "HTTP: ", log.Ldate|log.Ltime)

	// Do a request to log
	reqUrl := url.URL{
		Scheme: "http",
		Host:   s.addr,
		Path:   config.EndpointGetOpaBundles,
	}

	req, err := http.NewRequest(http.MethodGet, reqUrl.String(), nil)
	req.Header.Set("Authorization", "Bearer "+s.bundleAuth)
	assert.NoError(s.T(), err, "No error creating request")

	client := http.Client{}
	defer client.CloseIdleConnections()
	_, err = client.Do(req)
	assert.NoError(s.T(), err, "No error on logger bundle request")

	httpLog = origLog

	result := buf.String()
	assert.Contains(s.T(), result, "(Get Bundle) bundle@hexa.org")
}

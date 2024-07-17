package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hexa-org/policy-mapper/pkg/keysupport"
	"github.com/hexa-org/policy-mapper/pkg/mockOidcSupport"
	"github.com/hexa-org/policy-mapper/pkg/oauth2support"
	"github.com/hexa-org/policy-mapper/pkg/oidcSupport"
	"github.com/hexa-org/policy-mapper/pkg/websupport"
	"github.com/hexa-org/policy-opa/pkg/mockopasupport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	log "golang.org/x/exp/slog"
)

type testSuite struct {
	suite.Suite
	demoSrv    *http.Server
	client     *http.Client
	mockOpa    *mockopasupport.MockOPA
	mockOidc   *mockOidcSupport.MockAuthServer
	isLoggedIn bool
}

func TestSuite(t *testing.T) {

	_ = os.Setenv(oidcSupport.EnvOidcEnabled, "true")
	_ = os.Setenv("HEXAOPA_DETAIL", "full")
	demoListener, _ := net.Listen("tcp", "127.0.0.1:0")
	_ = os.Setenv(oidcSupport.EnvOidcRedirectUrl, "http://"+demoListener.Addr().String()+"/redirect")

	log.Info("Starting Mock OPA Server")
	mockOpa := mockopasupport.NewMockOPA(t, []byte(testPolicyString))
	defer mockOpa.Shutdown()
	_ = os.Setenv("OPA_SERVER_URL", mockOpa.GetQueryUrl())

	log.Info("Starting Mock OIDC Server")
	mockOidc := newMockAuthServer(t)
	defer mockOidc.Shutdown()

	log.Info("Starting Demo Server")
	demoServer := App(demoListener.Addr().String())
	go websupport.Start(demoServer, demoListener)
	defer websupport.Stop(demoServer)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := http.Client{}
	client.Jar = jar
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	ts := testSuite{
		demoSrv:    demoServer,
		mockOpa:    mockOpa,
		mockOidc:   mockOidc,
		client:     &client,
		isLoggedIn: false,
	}

	suite.Run(t, &ts)
}

func newMockAuthServer(t *testing.T) *mockOidcSupport.MockAuthServer {
	claims := map[string]interface{}{}
	mockAuth := mockOidcSupport.NewMockAuthServer("aClient", "secret", claims)
	mockerAddr := mockAuth.Server.URL
	mockUrlJwks, err := url.JoinPath(mockerAddr, "/jwks")
	assert.NoError(t, err)
	_ = os.Setenv(oauth2support.EnvOAuthJwksUrl, mockUrlJwks)
	_ = os.Setenv(oauth2support.EnvOAuthJwksUrl, mockUrlJwks)
	_ = os.Setenv(oidcSupport.EnvOidcClientId, "aClient")
	_ = os.Setenv(oidcSupport.EnvOidcClientSecret, "secret")
	_ = os.Setenv(oidcSupport.EnvOidcProviderUrl, mockerAddr)
	return mockAuth
}

func (ts *testSuite) execute(method string, urlPath string, tlsMode bool) (*http.Response, string) {
	destUrl := urlPath
	checkUrl, _ := url.Parse(urlPath)
	protocol := "http://"
	if tlsMode {
		protocol = "https://"
	}
	if checkUrl.Host == "" { // default to demo server
		destUrl = protocol + ts.demoSrv.Addr + urlPath
	}
	req, err := http.NewRequest(method, destUrl, nil)
	if err != nil {
		ts.T().Fatal(err)
	}

	rs, err := ts.client.Do(req)

	defer rs.Body.Close()
	body, err := io.ReadAll(rs.Body)
	if err != nil {
		ts.T().Fatal(err)
	}

	return rs, string(body)
}

func (ts *testSuite) doLogin(email string, roles []string) {
	if ts.isLoggedIn {
		ts.doLogout()
	}
	rs, body := ts.execute(http.MethodGet, "/authorize", false)
	// fmt.Println(body)
	assert.Equal(ts.T(), http.StatusFound, rs.StatusCode)
	authLocation, err := rs.Location()
	assert.NoError(ts.T(), err)

	// The mock ID token issued will be for alice who is in sales
	ts.mockOidc.TestEmail = email
	ts.mockOidc.TestRoles = roles

	log.Info("Redirecting to mock Oidc: " + authLocation.String())
	rs, body = ts.execute(http.MethodGet, authLocation.String(), false)
	assert.Equal(ts.T(), http.StatusFound, rs.StatusCode)

	callBackLocation, err := rs.Location()
	assert.NoError(ts.T(), err)
	log.Info("Executing callback to demo server: " + callBackLocation.String())

	log.Info("Calling Demo server /redirect callback endpoint: " + callBackLocation.String())
	rs, body = ts.execute(http.MethodGet, callBackLocation.String(), false)
	assert.Equal(ts.T(), http.StatusTemporaryRedirect, rs.StatusCode)

	defLocation, err := rs.Location()
	assert.NoError(ts.T(), err)

	log.Info("Going to default location: " + defLocation.String())
	rs, body = ts.execute(http.MethodGet, defLocation.String(), false)
	assert.Contains(ts.T(), body, email)
	assert.Contains(ts.T(), body, "Great news, you're able to access this page.")
	ts.isLoggedIn = true

	for _, c := range ts.client.Jar.Cookies(defLocation) {
		log.Info(fmt.Sprintf("Cookie: %s=%s", c.Name, c.Value))
	}
}

func (ts *testSuite) doLogout() {
	if ts.isLoggedIn {
		rs, _ := ts.execute(http.MethodGet, "/logout", false)
		assert.Equal(ts.T(), http.StatusTemporaryRedirect, rs.StatusCode)
	}
	ts.isLoggedIn = false
}

func (ts *testSuite) TestLogin() {
	ts.doLogin("alice@hexaindustries.io", nil)
	rs, body := ts.execute(http.MethodGet, "/dashboard", false)
	assert.Equal(ts.T(), http.StatusOK, rs.StatusCode)
	assert.Contains(ts.T(), body, "alice@hexaindustries.io")
	assert.Contains(ts.T(), body, "Great news, you're able to access this page.")
}

func (ts *testSuite) TestStatic() {
	ts.doLogout() // should not require a session
	rs, body := ts.execute(http.MethodGet, "/images/hexa.svg", false)
	assert.Equal(ts.T(), http.StatusOK, rs.StatusCode)
	assert.Contains(ts.T(), body, "<svg", "Should contain SVG file")
}

func (ts *testSuite) TestSales() {
	ts.doLogin("alice@hexaindustries.io", []string{"accounting"})

	rs, body := ts.execute(http.MethodGet, "/sales", false)
	assert.Equal(ts.T(), http.StatusOK, rs.StatusCode)
	assert.Contains(ts.T(), body, "Sorry, you're not able to access this page.")

	ts.doLogin("betty@hexaindustries.io", []string{"sales"})
	rs, body = ts.execute(http.MethodGet, "/sales", false)
	assert.Contains(ts.T(), body, "betty@hexaindustries.io")
	assert.Contains(ts.T(), body, "Great news, you're able to access this page.")
}

func (ts *testSuite) TestAccounting() {
	ts.doLogin("alice@hexaindustries.io", []string{"sales"})

	rs, body := ts.execute(http.MethodGet, "/accounting", false)
	assert.Equal(ts.T(), http.StatusOK, rs.StatusCode)
	assert.Contains(ts.T(), body, "Sorry, you're not able to access this page.")

	ts.doLogin("betty@hexaindustries.io", []string{"accounting"})
	rs, body = ts.execute(http.MethodGet, "/accounting", false)
	assert.Contains(ts.T(), body, "betty@hexaindustries.io")
	assert.Contains(ts.T(), body, "Great news, you're able to access this page.")
}

func (ts *testSuite) TestHumanResources() {
	ts.doLogin("alice@hexaindustries.io", []string{"sales"})

	rs, body := ts.execute(http.MethodGet, "/humanresources", false)
	assert.Equal(ts.T(), http.StatusOK, rs.StatusCode)
	assert.Contains(ts.T(), body, "Sorry, you're not able to access this page.")

	ts.doLogin("betty@hexaindustries.io", []string{"humanresources"})
	rs, body = ts.execute(http.MethodGet, "/humanresources", false)
	assert.Contains(ts.T(), body, "betty@hexaindustries.io")
	assert.Contains(ts.T(), body, "Great news, you're able to access this page.")
}

func (ts *testSuite) TestNoOidc() {
	ts.doLogout()
	_ = os.Setenv(oidcSupport.EnvOidcEnabled, "false")
	demoListener, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := demoListener.Addr().String()
	demoListener.Close()
	server, listener := newApp(addr)
	go websupport.Start(server, listener)
	defer server.Close()
	defer listener.Close()

	rs, _ := ts.execute(http.MethodGet, fmt.Sprintf("http://%s/", addr), false)
	assert.Equal(ts.T(), http.StatusTemporaryRedirect, rs.StatusCode)

	rs, body := ts.execute(http.MethodGet, fmt.Sprintf("http://%s/dashboard", addr), false)
	assert.Equal(ts.T(), http.StatusOK, rs.StatusCode)
	assert.Contains(ts.T(), body, "Great news, you're able to access this page.")

}

func (ts *testSuite) TestTls() {
	ts.doLogout()
	tempCertDir, _ := os.MkdirTemp("", "hexa-demo-test-*")

	_ = os.Setenv(keysupport.EnvCertDirectory, tempCertDir)
	_ = os.Setenv(oidcSupport.EnvOidcEnabled, "false")
	demoListener, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := demoListener.Addr().String()
	demoListener.Close()
	addrParts := strings.Split(addr, ":")

	// Use HOST and PORT to exercise environment variable config
	_ = os.Setenv("PORT", addrParts[1])
	_ = os.Setenv("HOST", addrParts[0])
	_ = os.Setenv(websupport.EnvTlsEnabled, "t")
	server, listener := newApp(addr)
	go websupport.Start(server, listener)

	defer func(path string) {
		server.Close()
		listener.Close()
		_ = os.RemoveAll(path)
	}(tempCertDir)

	_ = os.Setenv(keysupport.EnvCertCaPubKey, filepath.Join(tempCertDir, "ca-cert.pem"))
	keysupport.CheckCaInstalled(ts.client)

	rs, _ := ts.execute(http.MethodGet, fmt.Sprintf("https://%s/", addr), true)
	assert.Equal(ts.T(), http.StatusTemporaryRedirect, rs.StatusCode)

	rs, body := ts.execute(http.MethodGet, fmt.Sprintf("https://%s/dashboard", addr), true)
	assert.Equal(ts.T(), http.StatusOK, rs.StatusCode)
	assert.Contains(ts.T(), body, "Great news, you're able to access this page.")

}

var testPolicyString = `
{
  "policies": [
    {
      "meta": {
        "version": "0.6",
        "policyId": "getRootPage",
        "description": "Retrieve the root page open to anyone"
      },
      "actions": [
        {
          "actionUri": "http:GET:/dashboard"
        }
      ],
      "subject": {
        "members": [
          "any"
        ]
      },
      "object": {
        "resource_id": "hexaIndustries"
      }
    },
    {
      "meta": {
        "version": "0.6",
        "policyId": "getSales"
      },
      "actions": [
        {
          "actionUri": "sales"
        }
      ],
      "subject": {
        "members": [
          "role:sales",
          "role:marketing"
        ]
      },
      "object": {
        "resource_id": "hexaIndustries"
      }
    },
    {
      "meta": {
        "version": "0.6",
        "policyId": "getAccounting"
      },
      "actions": [
        {
          "actionUri": "http:GET:/accounting"
        },
        {
          "actionUri": "http:POST:/accounting"
        }
      ],
      "subject": {
        "members": [
          "role:accounting"
        ]
      },
      "object": {
        "resource_id": "hexaIndustries"
      }
    },
    {
      "meta": {
        "version": "0.6",
        "policyId": "getHumanResources"
      },
      "actions": [
        {
          "actionUri": "http:GET:/humanresources"
        }
      ],
      "subject": {
        "members": [
          "role:humanresources"
        ]
      },
      "object": {
        "resource_id": "hexaIndustries"
      }
    }
  ]
}`

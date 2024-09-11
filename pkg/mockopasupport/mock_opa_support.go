package mockopasupport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/hexa-org/policy-mapper/providers/openpolicyagent"
	"github.com/hexa-org/policy-opa/api/infoModel"
	"github.com/hexa-org/policy-opa/pkg/compressionsupport"
	"github.com/hexa-org/policy-opa/pkg/decisionsupportproviders"
	"github.com/hexa-org/policy-opa/server/opaHandler"
	"github.com/stretchr/testify/assert"
)

type MockOPA struct {
	regoHandler *opaHandler.RegoHandler
	Server      *httptest.Server
	t           *testing.T
	BundleDir   string
}

// NewMockOPA creates a mock OPA server for testing. policyBytes is the IDQL policy to be enforced. If nil, default hexaIndustries policy is used
func NewMockOPA(t *testing.T, policyBytes []byte) *MockOPA {
	m := &MockOPA{
		t: t,
	}
	m.initTestBundlesDir(policyBytes)
	m.regoHandler = opaHandler.NewRegoHandler(m.BundleDir)
	router := m.initHandlers()
	m.Server = newTestServer(t, router)

	return m
}

func (m *MockOPA) GetQueryUrl() string {
	return fmt.Sprintf("%s/v1/data/hexaPolicy", m.Server.URL)
}

func (m *MockOPA) initHandlers() *mux.Router {
	router := mux.NewRouter()

	router.HandleFunc("/v1/data/hexaPolicy", func(w http.ResponseWriter, r *http.Request) {
		var input decisionsupportproviders.OpaRestQuery
		err := json.NewDecoder(r.Body).Decode(&input)
		assert.NoError(m.t, err)
		azInput := infoModel.AzInfo{
			Req:      input.Input.Req,
			Subject:  input.Input.Subject,
			Resource: infoModel.ResourceInfo{},
		}
		results, err := m.regoHandler.Evaluate(azInput)
		opaRes := m.regoHandler.ProcessResults(results)
		response := decisionsupportproviders.OpaResponse{
			DecisionId: uuid.NewString(),
			Result:     *opaRes,
		}
		respBytes, err := json.Marshal(response)
		assert.NoError(m.t, err)
		_, err = w.Write(respBytes)
		assert.NoError(m.t, err, "Should be no error writing response")

	}).Methods("POST")

	return router
}

func newTestServer(t *testing.T, h http.Handler) *httptest.Server {
	ts := httptest.NewServer(h)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	ts.Client().Jar = jar

	ts.Client().CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return ts
}

func (m *MockOPA) initTestBundlesDir(data []byte) {
	m.BundleDir, _ = os.MkdirTemp("", "policy-opa-test-*")

	var databytes []byte
	if data == nil {
		databytes = []byte(policyString)
	} else {
		databytes = data
	}
	bundleBuf, _ := openpolicyagent.MakeHexaBundle(databytes)

	gzip, _ := compressionsupport.UnGzip(bytes.NewReader(bundleBuf.Bytes()))

	_ = compressionsupport.UnTarToPath(bytes.NewReader(gzip), m.BundleDir)

}

func (m *MockOPA) Shutdown() {
	m.Server.Close()

	_ = os.RemoveAll(m.BundleDir)
}

var policyString = `{
  "policies": [
    {
      "meta": {
        "version": "0.7",
        "policyId": "getRootPage",
        "description": "Retrieve the root page open to anyone"
      },
      "actions": [
        "http:GET:/dashboard"
      ],
      "subjects": [
        "any",
        "anyauthenticated"
      ],
      "object": "hexaIndustries"
    },
    {
      "meta": {
        "version": "0.7",
        "policyId": "getSales"
      },
      "actions": [
        "sales"
      ],
      "subjects": [
        "role:sales",
        "role:marketing"
      ],
      "object": "hexaIndustries"
    },
    {
      "meta": {
        "version": "0.7",
        "policyId": "getAccounting"
      },
      "actions": [
        "http:GET:/accounting",
        "http:POST:/accounting"
      ],
      "subjects": [
        "role:accounting"
      ],
      "object": "hexaIndustries"
    },
    {
      "meta": {
        "version": "0.7",
        "policyId": "getHumanResources"
      },
      "actions": [
        "http:GET:/humanresources"
      ],
      "subjects": [
        "role:humanresources"
      ],
      "object": "hexaIndustries"
    }
  ]
}`

package decisionsupportproviders_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/hexa-org/policy-opa/pkg/decisionsupportproviders"
	"github.com/open-policy-agent/opa/rego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestOpaDecisionProvider_BuildInput(t *testing.T) {
	provider := decisionsupportproviders.OpaDecisionProvider{
		Principal: "sales@hexaindustries.io",
	}

	req, _ := http.NewRequest("POST", "https://aDomain.com/noop", nil)
	req.RequestURI = "/noop"
	query, _ := provider.BuildInput(req, nil, nil)
	casted := query.(decisionsupportproviders.OpaQuery).Input
	assert.Equal(t, "POST", casted.Req.Method)
	assert.Equal(t, "aDomain.com", casted.Req.Host)
	assert.Equal(t, "/noop", casted.Req.Path)
	assert.Equal(t, "sales@hexaindustries.io", casted.Subject.Sub)
}

func TestOpaDecisionProvider_BuildInput_RemovesQueryParams(t *testing.T) {
	mockClient := new(MockClient)
	mockClient.response = []byte("{\"result\":true}")
	provider := decisionsupportproviders.OpaDecisionProvider{Client: mockClient, Url: "aUrl"}

	req, _ := http.NewRequest("GET", "http://aDomain.com/noop/?param=aParam", nil)
	req.RequestURI = "/noop"
	query, _ := provider.BuildInput(req, nil, nil)

	assert.Equal(t, "/noop/", query.(decisionsupportproviders.OpaQuery).Input.Req.Path)
}

type MockClient struct {
	mock.Mock
	response []byte
	err      error
}

func (m *MockClient) Do(_ *http.Request) (*http.Response, error) {
	r := io.NopCloser(bytes.NewReader(m.response))
	return &http.Response{StatusCode: 200, Body: r}, m.err
}

func TestOpaDecisionProvider_Allow(t *testing.T) {
	mockClient := new(MockClient)
	expressionValue := rego.ExpressionValue{
		Value: map[string]interface{}{
			"allow": true,
		},
		Text:     "data.hexaPolicy",
		Location: nil,
	}
	results := rego.ResultSet{
		rego.Result{
			Expressions: []*rego.ExpressionValue{&expressionValue},
			Bindings:    nil,
		},
	}
	resultBytes, _ := json.Marshal(results)
	mockClient.response = resultBytes
	provider := decisionsupportproviders.OpaDecisionProvider{Client: mockClient, Url: "aUrl"}

	req, _ := http.NewRequest("GET", "http://aDomain.com/noop", nil)
	req.RequestURI = "/noop"
	query, _ := provider.BuildInput(req, nil, nil)

	allow, _ := provider.Allow(query)
	assert.Equal(t, true, allow)
}

func TestOpaDecisionProvider_AllowWithRequestErr(t *testing.T) {
	mockClient := new(MockClient)
	mockClient.response = []byte("{\"result\":true}")
	mockClient.err = errors.New("oops")
	provider := decisionsupportproviders.OpaDecisionProvider{Client: mockClient, Url: "aUrl"}

	req, _ := http.NewRequest("GET", "http://aDomain.com/noop", nil)
	req.RequestURI = "/noop"
	query, _ := provider.BuildInput(req, nil, nil)

	allow, err := provider.Allow(query)
	assert.Error(t, err, "oops")
	assert.Equal(t, false, allow)
}

func TestOpaDecisionProvider_AllowWithResponseErr(t *testing.T) {
	mockClient := new(MockClient)
	mockClient.response = []byte("__bad__ {\"result\":true}")
	provider := decisionsupportproviders.OpaDecisionProvider{Client: mockClient, Url: "aUrl"}

	req, _ := http.NewRequest("GET", "http://aDomain.com/noop", nil)
	req.RequestURI = "/noop"
	query, _ := provider.BuildInput(req, nil, nil)

	allow, err := provider.Allow(query)
	assert.Error(t, err, "invalid character '_' looking for beginning of value")
	assert.Equal(t, false, allow)
}

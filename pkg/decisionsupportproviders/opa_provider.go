package decisionsupportproviders

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	opaTools "github.com/hexa-org/policy-opa/client/hexaOpaClient"
	"github.com/open-policy-agent/opa/rego"
)

type OpaDecisionProvider struct {
	Client    HTTPClient
	Url       string
	Principal string
}

type OpaQuery struct {
	Input *opaTools.OpaInfo `json:"input"`
}

func (o OpaDecisionProvider) BuildInput(r *http.Request, actionUris []string, resourceUris []string) (any interface{}, err error) {
	info := opaTools.PrepareInput(r, actionUris, resourceUris)
	if o.Principal != "" {
		info.Subject.Sub = o.Principal
	}

	return OpaQuery{info}, nil
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type OpaResponse struct {
	Result bool
}

func (o OpaDecisionProvider) Allow(any interface{}) (bool, error) {
	marshal, _ := json.Marshal(any.(OpaQuery))
	request, _ := http.NewRequest("POST", o.Url, bytes.NewBuffer(marshal))
	request.Header.Set("Content-Type", "application/json; charset=UTF-8")
	response, err := o.Client.Do(request)
	if err != nil {
		return false, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(response.Body)

	var jsonResponse rego.ResultSet
	err = json.NewDecoder(response.Body).Decode(&jsonResponse)
	if err != nil {
		return false, err
	}
	allow := processResults(jsonResponse)
	return allow, nil
}

func processResults(results rego.ResultSet) bool {
	if results == nil {
		return false
	}

	allowed := false
	result := results[0].Expressions[0]
	for k, _ := range result.Value.(map[string]interface{}) {

		if k == "allow" {
			allowed = true
		}
	}

	return allowed
}

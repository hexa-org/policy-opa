package decisionsupportproviders

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	opaTools "github.com/hexa-org/policy-opa/client/hexaOpaClient"
)

const EnvOpaDebug string = "HEXAOPA_DETAIL"

type OpaDecisionProvider struct {
	Client    HTTPClient
	Url       string
	Principal string
}

func (o OpaDecisionProvider) BuildInput(r *http.Request, actionUris []string, resourceUris []string) (any interface{}, err error) {
	info := opaTools.PrepareInput(r, actionUris, resourceUris)
	if o.Principal != "" {
		info.Subject.Sub = o.Principal
	}

	return info, nil
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type OpaRestQuery struct {
	Input opaTools.OpaInfo `json:"input"`
}

type HexaOpaResult struct {
	ActionRights      []string `json:"action_rights"`
	AllowSet          []string `json:"allow_set"`
	Allow             bool     `json:"allow"`
	PoliciesEvaluated int      `json:"policies_evaluated"`
	HexaRegoVersion   string   `json:"hexa_rego_version"`
}

type OpaResponse struct {
	DecisionId  string           `json:"decision_id"`
	Result      HexaOpaResult    `json:"result"`
	Warning     *json.RawMessage `json:"warning"`
	Explanation *json.RawMessage `json:"explanation"`
}

func (o OpaDecisionProvider) AllowQuery(any interface{}) (*HexaOpaResult, error) {
	info := any.(*opaTools.OpaInfo)
	input := OpaRestQuery{Input: *info}
	marshal, _ := json.Marshal(input)
	debugParams := ""
	debugMode := os.Getenv(EnvOpaDebug)
	if debugMode != "" {
		debugParams = fmt.Sprintf("?pretty=true&explain=%s", debugMode)
	}
	request, _ := http.NewRequest("POST", o.Url+debugParams, bytes.NewBuffer(marshal))
	request.Header.Set("Content-Type", "application/json; charset=UTF-8")
	response, err := o.Client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 400 {
		err = errors.New(fmt.Sprintf("Received error querying OPA: %s", response.Status))
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(response.Body)

	b, err := io.ReadAll(response.Body)
	if err != nil {
		log.Fatalln(err)
	}

	if debugParams != "" {
		log.Println("Decision output:")
		log.Println(string(b))
	}

	var jsonResponse OpaResponse
	// err = json.NewDecoder(b).Decode(&jsonResponse)
	err = json.Unmarshal(b, &jsonResponse)
	if err != nil {
		return nil, err
	}
	if jsonResponse.Warning != nil {
		log.Println(fmt.Sprintf("Rego warning:\n%s", jsonResponse.Warning))
	}
	log.Println(fmt.Sprintf("Decision: %s, Allow: %t", jsonResponse.DecisionId, jsonResponse.Result.Allow))
	// allow := processResults(jsonResponse)
	return &jsonResponse.Result, nil
}

func (o OpaDecisionProvider) Allow(any interface{}) (bool, error) {
	resp, err := o.AllowQuery(any)
	if err != nil {
		return false, err
	}
	return resp.Allow, nil
}

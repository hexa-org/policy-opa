package decisionsupportproviders

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hexa-org/policy-mapper/pkg/oidcSupport"
	log "golang.org/x/exp/slog"

	"github.com/hexa-org/policy-mapper/pkg/hexapolicy"
	opaTools "github.com/hexa-org/policy-opa/client/hexaOpaClient"
)

const EnvOpaDebug string = "HEXAOPA_DETAIL"

// A OpaDecisionProvider implements the DecisionProvider interface
// and is used to convert http request information and other contextual information
// to call a HexaOPA service for a policy decision
type OpaDecisionProvider struct {
	Client      HTTPClient
	Url         string
	Principal   string // Default principal
	OidcHandler *oidcSupport.OidcClientHandler
}

func (o OpaDecisionProvider) BuildInput(r *http.Request, actionUris []string, resourceUris []string) (any interface{}, err error) {

	var info *opaTools.OpaInfo
	if o.OidcHandler.Enabled {
		sessionInfo, _ := o.OidcHandler.SessionHandler.Session(r)
		info = opaTools.PrepareInputWithClaimsFunc(r, func() *jwt.MapClaims {
			if sessionInfo == nil || sessionInfo.RawToken == "" {
				return nil
			}
			claims := jwt.MapClaims{}
			err := o.OidcHandler.ParseIdTokenClaims(sessionInfo.RawToken, &claims)
			if err != nil {
				return nil
			}
			return &claims
		}, actionUris, resourceUris)
	} else {
		info = opaTools.PrepareInput(r, actionUris, resourceUris)
		if o.Principal != "" {
			info.Subject.Sub = o.Principal
		}
	}
	return info, nil
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type OpaRestQuery struct {
	Input opaTools.OpaInfo `json:"input"`
}

type ScopeObligation struct {
	PolicyID string               `json:"policyId"`
	Scope    hexapolicy.ScopeInfo `json:"scope"`
}

type PolicyParseError struct {
	PolicyId string `json:"policyId"`
	Error    string `json:"error"`
}

type HexaOpaResult struct {
	ActionRights      []string           `json:"action_rights"`        // lists the actions that are allowed by all policies matched
	AllowSet          []string           `json:"allow_set"`            // lists policyId values that matched
	DenySet           []string           `json:"deny_set"`             // lists policyId values of policies that matched with condition action 'deny'
	Allow             bool               `json:"allow"`                // set to true if denySet is 0 and allowSet > 0
	PoliciesEvaluated int                `json:"policies_evaluated"`   // total number of idql policies evaluated
	HexaRegoVersion   string             `json:"hexa_rego_version"`    // Current rego policy version used
	Scopes            []ScopeObligation  `json:"scopes,omitempty"`     // Scopes obligations returned from policies matched
	PolicyErrors      []PolicyParseError `json:"error_idql,omitempty"` // Parsing diagnostics detected at run time
}

type OpaResponse struct {
	DecisionId  string           `json:"decision_id"`
	Result      HexaOpaResult    `json:"result"`
	Warning     *json.RawMessage `json:"warning"`
	Explanation *json.RawMessage `json:"explanation"`
}

// AllowQuery calls the configured HexaOPA server and returns a parsed HexaOpaResult value.
// The any parameter is actually an opaTools.OpaInfo struct that contains contextual request information from BuildInput function.
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
		log.Error(fmt.Sprintf("Error communicating with OPA Server: %s", err.Error()))
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
		log.Error(err.Error())
	}

	if debugParams != "" {
		log.Info("Decision output:")
		log.Info(string(b))
	}

	var jsonResponse OpaResponse
	// err = json.NewDecoder(b).Decode(&jsonResponse)
	err = json.Unmarshal(b, &jsonResponse)
	if err != nil {
		return nil, err
	}
	if jsonResponse.Warning != nil {
		warn, _ := jsonResponse.Warning.MarshalJSON()
		log.Info(fmt.Sprintf("Rego warning:\n%s", string(warn)))
	}
	log.Info(fmt.Sprintf("Decision: %s, Allow: %t", jsonResponse.DecisionId, jsonResponse.Result.Allow))
	// allow := processResults(jsonResponse)
	return &jsonResponse.Result, nil
}

// Allow is a convenience method (similar to AllowQuery) that returns either a true or false policy decision result.
// The parameter any is usually the value from BuildInput func.
func (o OpaDecisionProvider) Allow(any interface{}) (bool, error) {
	resp, err := o.AllowQuery(any)
	if err != nil {
		return false, err
	}
	return resp.Allow, nil
}

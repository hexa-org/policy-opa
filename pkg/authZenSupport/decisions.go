// Package decisionHandler maps between AuthZen requests and calls opaHandler to process decisions. decisionHandler can
// be used as an SDK to run an embedded Hexa IDQL PDP.
package authZenSupport

import (
	"bytes"
	_ "embed"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/hexa-org/policy-mapper/providers/openpolicyagent"
	"github.com/hexa-org/policy-opa/api/infoModel"
	opaTools "github.com/hexa-org/policy-opa/client/hexaOpaClient"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/config"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/userHandler"
	"github.com/hexa-org/policy-opa/pkg/compressionsupport"
	"github.com/hexa-org/policy-opa/pkg/decisionsupportproviders"
	"github.com/hexa-org/policy-opa/server/opaHandler"
)

const (
	ResultBrief  = "brief"
	ResultDetail = "detail"
)

type DecisionHandler struct {
	pip          *infoModel.UserRecs
	regoHandler  *opaHandler.RegoHandler
	resultDetail string
}

// NewDecisionHandler is intended for use in a server (e.g. cmd/hexaAuthZen) where an http method handler requests decision handler
// to process decisions. Configuration and policy are handled through environment variables: AUTHZEN_BUNDLE_DIR, AUTHZEN_RESPONSE_DETAIL.
// On invocation, this method will attempt to locate and parse IDQL contained in data.json. If the JSON is not parsable or IDQL cannot be parsed
// an error is returned as the HexaOPA engine will not be able to process decisions. If `data.json` contains no policies, a warning is issued
// to the server log. This scenario assumes the bundle will be updated later and `ProcessUploadOpa` will be called. If no bundle directory is detected,
// An initial default bundle will be created (e.g. to support demos) using the bundle embedded in:
func NewDecisionHandler() (*DecisionHandler, error) {
	detail := os.Getenv(config.EnvAuthZenDecDetail)
	if strings.EqualFold(detail, ResultDetail) {
		detail = ResultDetail
	} else {
		detail = ResultBrief
	}

	bundlesDir := os.Getenv(config.EnvBundleDir)
	if bundlesDir == "" {
		bundlesDir = config.DefBundlePath
	}
	_, err := os.Stat(bundlesDir)
	if os.IsNotExist(err) {
		_ = os.Mkdir(bundlesDir, 0755)

	}

	// Check to see if a bundle folder exists, if not create a new AuthZen bundle
	bundleDir := filepath.Join(bundlesDir, "bundle")
	_, err = os.Stat(bundleDir)
	if os.IsNotExist(err) {
		createInitialBundle(bundlesDir)
	}

	handler, err := opaHandler.NewRegoHandler(bundlesDir)
	if err != nil {
		return nil, err
	}

	return &DecisionHandler{
		pip:          userHandler.NewUserPIP(""),
		regoHandler:  handler,
		resultDetail: detail,
	}, nil
}

func createInitialBundle(bundlePath string) {
	_, file, _, _ := runtime.Caller(0)
	basePolicy := filepath.Join(filepath.Dir(file), "../..", config.DemoAuthZenPolicy)
	dataBytes, err := os.ReadFile(basePolicy)
	if err != nil {
		config.ServerLog.Fatalf("unable to read default Authzen Policy: %s", err)
	}
	bundleBuffer, err := openpolicyagent.MakeHexaBundle(dataBytes)
	if err != nil {
		config.ServerLog.Fatalf("unexpected error creating and initializing Hexa Bundle: %s", err)
	}
	gzip, _ := compressionsupport.UnGzip(bytes.NewReader(bundleBuffer.Bytes()))

	_ = compressionsupport.UnTarToPath(bytes.NewReader(gzip), bundlePath)
}

// ProcessUploadOpa causes the OPA engine to reload policy and rego instructions from the bundle directory (see config.EnvBundleDir).
// To update the HexaOPA decision engine, update the bundle directory contents and call this method to reload.
func (d *DecisionHandler) ProcessUploadOpa() error {
	return d.regoHandler.ReloadRego()
}

func (d *DecisionHandler) createInputObjectSimple(authRequest infoModel.EvaluationItem, resources *[]string) infoModel.AzInfo {
	var user *infoModel.UserInfo
	if authRequest.Subject != nil && authRequest.Subject.Id != "" {
		user = d.pip.GetUser(authRequest.Subject.Id)
	}

	claims := make(map[string]interface{})
	var subject opaTools.SubjectInfo
	if user != nil {
		// if no user located or assserted, there is nothing to set
		claims["email"] = user.Email
		claims["picture"] = user.Picture
		claims["name"] = user.Name
		claims["id"] = user.Id
		subject = opaTools.SubjectInfo{
			Roles:  user.Roles,
			Sub:    authRequest.Subject.Id,
			Claims: claims,
		}
	}

	var actions []string

	if authRequest.Action != nil {
		actions = []string{authRequest.Action.Name}
	}

	var reqParams opaTools.ReqParams

	reqParams = opaTools.ReqParams{
		ActionUris:  actions,
		ResourceIds: *resources,
	}

	var resource infoModel.ResourceInfo
	if authRequest.Resource != nil {
		resource = *authRequest.Resource
	}
	return infoModel.AzInfo{
		Req:      &reqParams,
		Subject:  &subject,
		Resource: resource,
	}

}

// HealthCheck actively calls the HexaOPA engine for a decision based on empty input. As long as an error is not
// thrown, true is returned. This is intended to check that the OPA instance is running.
func (d *DecisionHandler) HealthCheck() bool {
	return d.regoHandler != nil && d.regoHandler.HealthCheck()
}

/*
ProcessDecision takes an AuthZen AuthRequest, generates a Hexa OPA input object that combines resource, subject, and
request information and calls the HexaOPA decision engine and parses the results.
*/
func (d *DecisionHandler) ProcessDecision(authRequest infoModel.EvaluationItem) (*infoModel.DecisionResponse, error, int) {

	input := d.createInputObjectSimple(authRequest, &[]string{"todo"})

	results, err := d.regoHandler.Evaluate(input)

	if err != nil {
		return nil, err, 500
	}
	result := d.regoHandler.ProcessResults(results)

	// process response
	if result.Allow == true {
		return &infoModel.DecisionResponse{Decision: true}, nil, 200
	}
	return &infoModel.DecisionResponse{Decision: false}, nil, 200
}

func (d *DecisionHandler) convertResult(result *decisionsupportproviders.HexaOpaResult, evalErr error) infoModel.DecisionResponse {

	context := infoModel.ContextInfo{}
	now := time.Now()
	context["time"] = now

	allow := false
	if result != nil {
		context["PoliciesEvaluated"] = result.PoliciesEvaluated
		context["HexaRegoVersion"] = result.HexaRegoVersion
		context["AllowSet"] = result.AllowSet
		context["ActionRights"] = result.ActionRights
		if result.PolicyErrors != nil {
			context["PolicyErrors"] = result.PolicyErrors
		}
		if result.Scopes != nil {
			context["Scopes"] = result.Scopes
		}
		allow = result.Allow
	}

	if evalErr != nil {
		errMap := make(map[string]interface{})
		errMap["status"] = 500
		errMap["message"] = evalErr.Error()
		context["error"] = errMap
		return infoModel.DecisionResponse{Decision: false, Context: &context}
	}

	if d.resultDetail == ResultDetail {
		return infoModel.DecisionResponse{Decision: allow, Context: &context}
	}

	// TODO Authzen interop currently not accepting context attribute
	return infoModel.DecisionResponse{Decision: allow}
}

// ProcessQueryDecision takes an AuthZen Query request processes each query into an HexaOPA decision and returns a response
func (d *DecisionHandler) ProcessQueryDecision(query infoModel.QueryRequest, _ *http.Request) (*infoModel.EvaluationsResponse, error, int) {

	items := query.EvaluationItems()
	decisionResponses := make([]infoModel.DecisionResponse, len(items))
	for i, item := range items {
		input := d.createInputObjectSimple(item, &[]string{"todo"})

		results, evalErr := d.regoHandler.Evaluate(input)
		result := d.regoHandler.ProcessResults(results)
		decisionResponses[i] = d.convertResult(result, evalErr)
	}
	return &infoModel.EvaluationsResponse{
		Evaluations: &decisionResponses,
	}, nil, http.StatusOK
}

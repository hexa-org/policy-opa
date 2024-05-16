// Package decisionHandler maps between AuthZen requests and the HexaOPA IDQL based engine
package decisionHandler

import (
	"bytes"
	_ "embed"
	"net/http"
	"os"
	"path/filepath"

	"github.com/hexa-org/policy-mapper/providers/openpolicyagent"
	infoModel2 "github.com/hexa-org/policy-opa/api/infoModel"
	opaTools "github.com/hexa-org/policy-opa/client/hexaOpaClient"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/config"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/userHandler"
	"github.com/hexa-org/policy-opa/pkg/compressionsupport"
	"github.com/hexa-org/policy-opa/server/opaHandler"
)

type DecisionHandler struct {
	pip         *userHandler.UserIP
	regoHandler *opaHandler.RegoHandler
}

func NewDecisionHandler() *DecisionHandler {
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

	return &DecisionHandler{
		pip:         userHandler.NewUserPIP(""),
		regoHandler: opaHandler.NewRegoHandler(bundlesDir),
	}
}

func createInitialBundle(bundlePath string) {
	dataBytes, err := os.ReadFile(config.BaseAuthZenPolicy)
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

func (d *DecisionHandler) ProcessUploadOpa() error {
	return d.regoHandler.ReloadRego()
}

func (d *DecisionHandler) createInputObjectSimple(authRequest infoModel2.AuthRequest) infoModel2.AzInfo {
	user := d.pip.GetUser(authRequest.Subject.Identity)

	claims := make(map[string]interface{})
	claims["email"] = user.Email
	claims["picture"] = user.Picture
	claims["name"] = user.Name
	claims["id"] = user.Id

	subject := opaTools.SubjectInfo{
		Roles:  user.Roles,
		Sub:    user.Sub,
		Claims: claims,
	}

	actions := []string{authRequest.Action.Name}
	reqParams := opaTools.ReqParams{
		ActionUris:  actions,
		ResourceIds: []string{"todo"},
	}

	return infoModel2.AzInfo{
		Req:      &reqParams,
		Subject:  &subject,
		Resource: authRequest.Resource,
	}

}

func (d *DecisionHandler) HealthCheck() bool {
	return d.regoHandler != nil && d.regoHandler.HealthCheck()
}

/*
ProcessDecision takes an AuthZen AuthRequest, generates a Hexa OPA input object that combines resource, subject, and
request information and calls the HexaOPA decision engine and parses the results.
*/
func (d *DecisionHandler) ProcessDecision(authRequest infoModel2.AuthRequest) (*infoModel2.SimpleResponse, error, int) {

	input := d.createInputObjectSimple(authRequest)

	results, err := d.regoHandler.Evaluate(input)
	if err != nil {
		return nil, err, 500
	}
	result := d.regoHandler.ProcessResults(results)

	// process response
	if result.Allow == true {
		return &infoModel2.SimpleResponse{Decision: true}, nil, 200
	}
	return &infoModel2.SimpleResponse{Decision: false}, nil, 200
}

// ProcessQueryDecision takes an AuthZen Query request processes each query into an HexaOPA decision and returns a response
func (d *DecisionHandler) ProcessQueryDecision(_ infoModel2.QueryRequest, _ *http.Request) (*infoModel2.EvaluationsResponse, error, int) {
	// TODO: Implement Process query decision
	return nil, nil, http.StatusNotImplemented
}

// Package decisionHandler maps between AuthZen requests and the HexaOPA IDQL based engine
package decisionHandler

import (
	"net/http"

	infoModel2 "github.com/hexa-org/policy-opa/api/infoModel"
	opaTools "github.com/hexa-org/policy-opa/client/hexaOpaClient"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/userHandler"
	"github.com/hexa-org/policy-opa/server/opaHandler"
)

type DecisionHandler struct {
	pip         *userHandler.UserIP
	regoHandler *opaHandler.RegoHandler
}

func NewDecisionHandler() *DecisionHandler {
	return &DecisionHandler{
		pip:         userHandler.NewUserPIP(""),
		regoHandler: opaHandler.NewRegoHandler(),
	}
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
	allowed, _, _ := d.regoHandler.ProcessResults(results)

	// process response
	if allowed == "true" {
		return &infoModel2.SimpleResponse{true}, nil, 200
	}
	return &infoModel2.SimpleResponse{false}, nil, 200
}

// ProcessQueryDecision takes an AuthZen Query request processes each query into an HexaOPA decision and returns a response
func (d *DecisionHandler) ProcessQueryDecision(_ infoModel2.QueryRequest, _ *http.Request) (*infoModel2.EvaluationsResponse, error, int) {
	// TODO: Implement Process query decision
	return nil, nil, http.StatusNotImplemented
}

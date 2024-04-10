package decisionHandler

import (
	"net/http"

	opaTools "github.com/hexa-org/policy-opa/client/hexaOpaClient"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/infoModel"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/opaHandler"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/userHandler"
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

func (d *DecisionHandler) createInputObjectSimple(authRequest infoModel.AuthRequest, r *http.Request) infoModel.AzInfo {
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

	return infoModel.AzInfo{
		Req:      &reqParams,
		Subject:  &subject,
		Resource: authRequest.Resource,
	}

}

func (d *DecisionHandler) ProcessDecision(authRequest infoModel.AuthRequest, r *http.Request) (*infoModel.SimpleResponse, error, int) {

	input := d.createInputObjectSimple(authRequest, r)

	results, err := d.regoHandler.Evaluate(input)
	if err != nil {
		return nil, err, 500
	}
	allowed, _, _ := d.regoHandler.ProcessResults(results)

	// process response
	if allowed == "true" {
		return &infoModel.SimpleResponse{true}, nil, 200
	}
	return &infoModel.SimpleResponse{false}, nil, 200
}

func (d *DecisionHandler) ProcessQueryDecision(authRequest infoModel.QueryRequest, r *http.Request) (*infoModel.EvaluationsResponse, error) {

	return nil, nil
}

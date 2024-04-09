package opaHandler

import (
	"testing"

	opaTools "github.com/hexa-org/policy-opa/client/hexaOpaClient"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/infoModel"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/userHandler"
	"github.com/stretchr/testify/assert"
)

func TestOpaHandler(t *testing.T) {
	pip := userHandler.NewUserPIP("../resources/users.json")

	// Testing with Beth
	user := pip.GetUser("CiRmZDM2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs")
	assert.NotNil(t, user, "Get User")
	handler := NewRegoHandler()

	claims := make(map[string]interface{})
	claims["email"] = user.Email
	claims["picture"] = user.Picture
	claims["name"] = user.Name
	claims["id"] = user.Id

	subject := opaTools.SubjectInfo{
		Roles:  user.Roles,
		Sub:    user.Sub,
		Claims: claims,
		Type:   "jwt",
	}

	actions := []string{"can_read_todos"}
	reqParams := opaTools.ReqParams{
		ActionUris:  actions,
		ResourceIds: []string{"todo"},
	}

	input := infoModel.AzInfo{
		Req:      &reqParams,
		Subject:  &subject,
		Resource: infoModel.ResourceInfo{},
	}

	results, err := handler.Evaluate(input)
	assert.NoError(t, err, "Evaluation completes")
	assert.NotNil(t, results, "Results returned")

	allowed, aSet, aRights := handler.ProcessResults(results)

	assert.Equal(t, "true", allowed, "allowed is true")
	assert.Greater(t, len(aSet), 0, "At least one rule")
	assert.Greater(t, len(aRights), 0, "At least one right")

	actions = []string{"can_create_todo"}
	reqParams.ActionUris = actions

	results, err = handler.Evaluate(input)
	assert.NoError(t, err, "Evaluation completes")
	assert.NotNil(t, results, "Results returned")

	allowed, aSet, aRights = handler.ProcessResults(results)

	assert.Equal(t, "false", allowed, "allowed is true")
	assert.Equal(t, len(aSet), 0, "No allows rule")
	assert.Equal(t, len(aRights), 0, "No right")

	// now with morty
	user = pip.GetUser("CiRmZDE2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs")
	assert.NotNil(t, user, "Get User")

	claims = make(map[string]interface{})
	claims["email"] = user.Email
	claims["picture"] = user.Picture
	claims["name"] = user.Name
	claims["id"] = user.Id

	subject = opaTools.SubjectInfo{
		Roles:  user.Roles,
		Sub:    user.Sub,
		Claims: claims,
		Type:   "jwt",
	}

	input = infoModel.AzInfo{
		Req:      &reqParams,
		Subject:  &subject,
		Resource: infoModel.ResourceInfo{},
	}

	results, err = handler.Evaluate(input)
	assert.NoError(t, err, "Evaluation completes")
	assert.NotNil(t, results, "Results returned")

	allowed, aSet, aRights = handler.ProcessResults(results)

	assert.Equal(t, "true", allowed, "allowed is true")
	assert.Greater(t, len(aSet), 0, "At least one rule")
	assert.Greater(t, len(aRights), 0, "At least one right")
}

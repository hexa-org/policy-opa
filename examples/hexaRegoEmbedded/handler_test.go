package hexaRegoEmbedded

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/hexa-org/policy-mapper/providers/openpolicyagent"
	infoModel2 "github.com/hexa-org/policy-opa/api/infoModel"
	opaTools "github.com/hexa-org/policy-opa/client/hexaOpaClient"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/config"
	"github.com/hexa-org/policy-opa/pkg/compressionsupport"
	"github.com/hexa-org/policy-opa/pkg/decisionsupportproviders"
	"github.com/hexa-org/policy-opa/server/opaHandler"
	"github.com/open-policy-agent/opa/topdown"
	assert "github.com/stretchr/testify/require"
)

const policyIDQL = `
{
    "policies": [
        {
            "meta": {
                "policyId": "GetOrganizationResource",
                "version": "0.7",
                "description": "A user must belong to an organization to access it's resources'"
            },
            "subjects": [
                "role:my-organization-id"
            ],
            "actions": [],
            "object": "arn:maverics:us-west:organization-id"
        }
    ]
}
`

func NewDecisionHandler() *opaHandler.RegoHandler {
	bundlesDir := "/tmp/bundles"
	_, err := os.Stat(filepath.Join(bundlesDir, "bundle"))
	if os.IsNotExist(err) {
		_ = os.Mkdir(bundlesDir, 0755)
		createInitialBundle(bundlesDir)
	} else {
		// do this so we can edit the rego to test
		os.WriteFile(filepath.Join(bundlesDir, "bundle", "data.json"), []byte(policyIDQL), 0644)
	}

	return opaHandler.NewRegoHandler(bundlesDir)
}

func createInitialBundle(bundlePath string) {
	os.RemoveAll(bundlePath)
	os.MkdirAll(bundlePath, 0755)
	bundleBuffer, err := openpolicyagent.MakeHexaBundle([]byte(policyIDQL))
	if err != nil {
		config.ServerLog.Fatalf("unexpected error creating and initializing Hexa Bundle: %s", err)
	}
	gzip, _ := compressionsupport.UnGzip(bytes.NewReader(bundleBuffer.Bytes()))

	_ = compressionsupport.UnTarToPath(bytes.NewReader(gzip), bundlePath)
}

func TestIDQL(t *testing.T) {
	os.Setenv(decisionsupportproviders.EnvOpaDebug, "debug")
	regoHandler := NewDecisionHandler()

	claims := make(map[string]interface{})
	claims["email"] = "rick@the-citadel.com"
	claims["picture"] = "https://www.topaz.sh/assets/templates/citadel/img/Rick%20Sanchez.jpg"
	claims["name"] = "Rick Sanchez"
	claims["id"] = "rick@the-citadel.com"

	subject := opaTools.SubjectInfo{
		// These are the roles the user must have
		Roles:  []string{"admin", "my-organization-id"},
		Sub:    "CiRmZDA2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs",
		Claims: claims,
	}

	reqParams := opaTools.ReqParams{
		ActionUris:  []string{"viewApplication"},
		ResourceIds: []string{"arn:maverics:us-west:organization-id:applications:application-id", "arn:maverics:us-west:organization-id"},
	}

	input := infoModel2.AzInfo{
		Req:      &reqParams,
		Subject:  &subject,
		Resource: infoModel2.ResourceInfo{},
	}

	results, err := regoHandler.Evaluate(input)
	assert.NoError(t, err)
	assert.NotNil(t, results)

	buffer := new(bytes.Buffer)
	if regoHandler.Tracer != nil {
		topdown.PrettyTraceWithLocation(buffer, *regoHandler.Tracer)
	}
	fmt.Println(buffer.String())

	result := regoHandler.ProcessResults(results)
	assert.NotNil(t, result)
	assert.True(t, result.Allow)
}

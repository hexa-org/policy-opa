package authZenApp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/hexa-org/policy-mapper/pkg/oauth2support"
	"github.com/hexa-org/policy-mapper/pkg/tokensupport"
	"github.com/hexa-org/policy-opa/api/infoModel"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/config"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/userHandler"
	"github.com/hexa-org/policy-opa/pkg/authZenSupport"
	"github.com/hexa-org/policy-opa/pkg/bundleTestSupport"
	"github.com/hexa-org/policy-opa/pkg/compressionsupport"
	"github.com/stretchr/testify/assert"
)

func TestGetBundle(t *testing.T) {
	testBundle := bundleTestSupport.InitTestBundlesDir(nil)
	defer bundleTestSupport.Cleanup(testBundle)

	az := AuthZenApp{bundleDir: testBundle}

	rr := httptest.NewRecorder()

	az.BundleDownload(rr, nil)

	assert.Equal(t, http.StatusOK, rr.Code, "Check status ok")
	bodyBuf := rr.Body

	gzip, err := compressionsupport.UnGzip(bodyBuf)
	assert.NoError(t, err, "Body was unzipped")

	tempDir, err := os.MkdirTemp("", "authzen-*")
	assert.NoError(t, err, "No error creating tempdir")
	defer bundleTestSupport.Cleanup(tempDir)

	err = compressionsupport.UnTarToPath(bytes.NewReader(gzip), tempDir)

	_, err = os.Stat(filepath.Join(tempDir, "bundle", "hexaPolicy.rego"))
	assert.NoError(t, err, "Rego should be there")

	_, err = os.Stat(filepath.Join(tempDir, "bundle", "data.json"))
	assert.NoError(t, err, "Rego should be there")
}

func TestUploadBundle(t *testing.T) {
	bundleDir := bundleTestSupport.InitTestBundlesDir(nil)
	defer bundleTestSupport.Cleanup(bundleDir)

	_ = os.Setenv(config.EnvBundleDir, bundleDir)
	az := AuthZenApp{bundleDir: bundleDir}
	az.Decision, _ = authZenSupport.NewDecisionHandler()

	bundleDir2 := bundleTestSupport.InitTestBundlesDir(nil)
	req, err := bundleTestSupport.PrepareBundleUploadRequest(bundleTestSupport.GetTestBundlePath(bundleDir2))
	assert.NoError(t, err, "No error creating request")
	rr := httptest.NewRecorder()

	az.BundleUpload(rr, req)
	assert.Equal(t, http.StatusCreated, rr.Code)

}

func TestBadPolicyStartup(t *testing.T) {

	policyPath := filepath.Join(bundleTestSupport.GetTestBundlePath("./test/badDataBundle"), "bundle", "data.json")
	databytes, err := os.ReadFile(policyPath)
	assert.NoError(t, err, "Check no error reading policy")
	bundleDir := bundleTestSupport.InitTestBundlesDir(databytes)
	defer bundleTestSupport.Cleanup(bundleDir)
	_ = os.Setenv(config.EnvBundleDir, bundleDir)

	az := AuthZenApp{bundleDir: bundleDir}
	az.Decision, err = authZenSupport.NewDecisionHandler()
	assert.Error(t, err, "unexpected end of JSON input")
	assert.Nil(t, az.Decision)

}

func TestUploadBadBundle(t *testing.T) {
	bundleDir := bundleTestSupport.InitTestBundlesDir(nil)
	defer bundleTestSupport.Cleanup(bundleDir)

	var err error
	_ = os.Setenv(config.EnvBundleDir, bundleDir)
	az := AuthZenApp{bundleDir: bundleDir}
	az.Decision, err = authZenSupport.NewDecisionHandler()
	assert.Nil(t, err)

	req, err := bundleTestSupport.PrepareBundleUploadRequest(bundleTestSupport.GetTestBundlePath("./test/badRegoBundle"))
	assert.NoError(t, err, "No error creating request")
	rr := httptest.NewRecorder()

	az.BundleUpload(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, "rego_parse_error", "Check error reported")

	req, err = bundleTestSupport.PrepareBundleUploadRequest(bundleTestSupport.GetTestBundlePath("./test/badDataBundle"))
	assert.NoError(t, err, "No error creating request")
	rr = httptest.NewRecorder()

	az.BundleUpload(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	body = rr.Body.String()
	assert.Contains(t, body, "data.json: unexpected EOF", "Check error reported")
}

func TestHandleEvaluation(t *testing.T) {
	bundleDir := bundleTestSupport.InitTestBundlesDir(nil)
	defer bundleTestSupport.Cleanup(bundleDir)

	_ = os.Setenv(config.EnvBundleDir, bundleDir)
	_ = os.Setenv(config.EnvAuthUserPipFile, userHandler.DefaultUserPipFile())
	az := AuthZenApp{bundleDir: bundleDir}
	az.Decision, _ = authZenSupport.NewDecisionHandler()

	body := infoModel.EvaluationItem{
		Subject: &infoModel.SubjectInfo{Id: "CiRmZDM2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"},
		Action:  &infoModel.ActionInfo{Name: "can_read_todos"},
	}

	bodyBytes, err := json.Marshal(&body)
	assert.NoError(t, err, "Check no error serializing request")
	req, err := http.NewRequest("POST", config.EndpointAuthzenSingleDecision, bytes.NewReader(bodyBytes))
	assert.NotNil(t, req)
	req.Header.Set(config.HeaderRequestId, "1234")
	rr := httptest.NewRecorder()
	az.HandleEvaluation(rr, req)

	assert.Equal(t, "1234", rr.Header().Get(config.HeaderRequestId), "Check request id is returned")
	assert.Equal(t, http.StatusOK, rr.Code, "Request processed ok")
	bodyBytes = rr.Body.Bytes()

	var simpleResponse infoModel.DecisionResponse
	err = json.Unmarshal(bodyBytes, &simpleResponse)
	assert.NoError(t, err, "response was parsed")
	assert.True(t, simpleResponse.Decision, "check decision is true")
}

func TestHandleQueryEvaluation(t *testing.T) {
	bundleDir := bundleTestSupport.InitTestBundlesDir(nil)
	defer bundleTestSupport.Cleanup(bundleDir)

	_ = os.Setenv(config.EnvBundleDir, bundleDir)
	_ = os.Setenv(config.EnvAuthUserPipFile, userHandler.DefaultUserPipFile())
	az := AuthZenApp{bundleDir: bundleDir}
	az.Decision, _ = authZenSupport.NewDecisionHandler()

	defaultItem := infoModel.EvaluationItem{
		Subject: &infoModel.SubjectInfo{Id: "CiRmZDM2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"},
	}
	body := infoModel.QueryRequest{
		EvaluationItem: &defaultItem,
		Evaluations: &infoModel.EvaluationBlock{
			Items: &[]infoModel.EvaluationItem{{
				Action: &infoModel.ActionInfo{Name: "can_update_todo"},
			}},
		},
	}

	bodyBytes, err := json.Marshal(&body)
	assert.NoError(t, err, "Check no error serializing request")
	req, err := http.NewRequest("POST", config.EndpointAuthzenQuery, bytes.NewReader(bodyBytes))
	req.Header.Set(config.HeaderRequestId, "1234")
	rr := httptest.NewRecorder()
	az.HandleQueryEvaluation(rr, req)

	assert.Equal(t, "1234", rr.Header().Get(config.HeaderRequestId), "Check request id is returned")
	assert.Equal(t, http.StatusOK, rr.Code, "Request processed ok")

}

func TestHandleSecurity(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	authzenPolicy := filepath.Join(file, "../../resources/data.json")
	todoPolicyBytes, err := os.ReadFile(authzenPolicy)
	assert.NoError(t, err)
	bundleDir := bundleTestSupport.InitTestBundlesDir(todoPolicyBytes)
	defer bundleTestSupport.Cleanup(bundleDir)

	_ = os.Setenv(tokensupport.EnvTknPrivateKeyFile, filepath.Join(bundleDir, "certs", tokensupport.DefTknPrivateKeyFile))
	tokenHandler, err := tokensupport.GenerateIssuerKeys("authzen", false)
	assert.NoError(t, err, "Check no errors generating keys")
	assert.NotNil(t, tokenHandler, "Check token handler returned")

	authToken, err := tokenHandler.IssueToken([]string{tokensupport.ScopeDecision}, "handlers@hexa.org")
	assert.NotNil(t, authToken)

	assert.NoError(t, err, "No error generating token")

	_ = os.Setenv(config.EnvBundleDir, bundleDir)
	_ = os.Setenv(config.EnvAuthUserPipFile, userHandler.DefaultUserPipFile())
	az := AuthZenApp{bundleDir: bundleDir}
	az.Decision, _ = authZenSupport.NewDecisionHandler()
	_ = os.Unsetenv(oauth2support.EnvOAuthJwksUrl)
	_ = os.Setenv(oauth2support.EnvTknPubKeyFile, tokenHandler.PublicKeyPath)
	_ = os.Setenv(oauth2support.EnvJwtKid, "authzen")
	_ = os.Setenv(oauth2support.EnvJwtAudience, "authzen")
	_ = os.Setenv(oauth2support.EnvJwtAuth, "true")

	az.TokenAuthorizer, err = oauth2support.NewResourceJwtAuthorizer()

	body := infoModel.EvaluationItem{
		Subject: &infoModel.SubjectInfo{Id: "CiRmZDM2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"},
		Action:  &infoModel.ActionInfo{Name: "can_read_todos"},
	}

	bodyBytes, err := json.Marshal(&body)
	assert.NoError(t, err, "Check no error serializing request")
	req, err := http.NewRequest("POST", config.EndpointAuthzenSingleDecision, bytes.NewReader(bodyBytes))
	req.Header.Set(config.HeaderRequestId, "1234")
	req.Header.Set("Authorization", "Bearer "+authToken)
	rr := httptest.NewRecorder()

	jwtHandler := oauth2support.JwtAuthenticationHandler(az.HandleEvaluation, az.TokenAuthorizer, []string{tokensupport.ScopeDecision})
	jwtHandler.ServeHTTP(rr, req)

	assert.Equal(t, "1234", rr.Header().Get(config.HeaderRequestId), "Check request id is returned")
	assert.Equal(t, http.StatusOK, rr.Code, "Request processed ok")
	bodyBytes = rr.Body.Bytes()

	var simpleResponse infoModel.DecisionResponse
	err = json.Unmarshal(bodyBytes, &simpleResponse)
	assert.NoError(t, err, "response was parsed")
	assert.True(t, simpleResponse.Decision, "check decision is true")

	req.Header.Del("Authorization")
	rr = httptest.NewRecorder()
	jwtHandler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code, "Request is unauthorized")

	bundleHandler := oauth2support.JwtAuthenticationHandler(az.BundleDownload, az.TokenAuthorizer, []string{tokensupport.ScopeBundle})

	req, err = http.NewRequest("GET", config.EndpointGetOpaBundles, nil)
	req.Header.Set("Authorization", "Bearer "+authToken)
	rr = httptest.NewRecorder()
	bundleHandler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code, "Check request is forbidden")

	testFail := `{
        "subject": {
          "type": "user",
          "id": "CiRmZDE2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"
        },
        "action": {
          "name": "can_update_todo"
        },
        "resource": {
          "type": "todo",
          "id": "7240d0db-8ff0-41ec-98b2-34a096273b9f",
          "properties": {
            "ownerID": "rick@the-citadel.com"
          }
        }
      }`

	req, err = http.NewRequest("POST", config.EndpointAuthzenSingleDecision, bytes.NewBufferString(testFail))
	req.Header.Set(config.HeaderRequestId, "1234")
	req.Header.Set("Authorization", "Bearer "+authToken)
	rr = httptest.NewRecorder()
	jwtHandler.ServeHTTP(rr, req)

	assert.Equal(t, "1234", rr.Header().Get(config.HeaderRequestId), "Check request id is returned")
	assert.Equal(t, http.StatusOK, rr.Code, "Request processed ok")
	bodyBytes = rr.Body.Bytes()

	err = json.Unmarshal(bodyBytes, &simpleResponse)
	assert.NoError(t, err, "response was parsed")
	assert.False(t, simpleResponse.Decision, "check decision is false")

	testShouldBeAllowed := `{
        "subject": {
          "type": "user",
          "id": "CiRmZDE2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"
        },
        "action": {
          "name": "can_update_todo"
        },
        "resource": {
          "type": "todo",
          "id": "7240d0db-8ff0-41ec-98b2-34a096273b9f",
          "properties": {
            "ownerID": "morty@the-citadel.com"
          }
        }
      }`

	req, err = http.NewRequest("POST", config.EndpointAuthzenSingleDecision, bytes.NewBufferString(testShouldBeAllowed))
	req.Header.Set(config.HeaderRequestId, "5678")
	req.Header.Set("Authorization", "Bearer "+authToken)
	rr = httptest.NewRecorder()
	jwtHandler.ServeHTTP(rr, req)

	assert.Equal(t, "5678", rr.Header().Get(config.HeaderRequestId), "Check request id is returned")
	assert.Equal(t, http.StatusOK, rr.Code, "Request processed ok")
	bodyBytes = rr.Body.Bytes()

	err = json.Unmarshal(bodyBytes, &simpleResponse)
	assert.NoError(t, err, "response was parsed")
	assert.True(t, simpleResponse.Decision, "check decision is true")
}

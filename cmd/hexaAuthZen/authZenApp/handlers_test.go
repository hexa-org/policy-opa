package authZenApp

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/hexa-org/policy-opa/api/infoModel"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/config"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/decisionHandler"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/userHandler"
	"github.com/hexa-org/policy-opa/pkg/compressionsupport"
	"github.com/hexa-org/policy-opa/pkg/tokensupport"
	"github.com/stretchr/testify/assert"
)

func cleanup(path string) {
	_ = os.RemoveAll(path)
}

func TestGetBundle(t *testing.T) {
	az := AuthZenApp{bundleDir: "./test/bundles"}

	rr := httptest.NewRecorder()

	az.BundleDownload(rr, nil)

	assert.Equal(t, http.StatusOK, rr.Code, "Check status ok")
	bodyBuf := rr.Body

	gzip, err := compressionsupport.UnGzip(bodyBuf)
	assert.NoError(t, err, "Body was unzipped")

	tempDir, err := os.MkdirTemp("", "authzen-*")
	assert.NoError(t, err, "No error creating tempdir")
	defer cleanup(tempDir)

	err = compressionsupport.UnTarToPath(bytes.NewReader(gzip), tempDir)

	_, err = os.Stat(filepath.Join(tempDir, "hexaPolicyV2.rego"))
	assert.NoError(t, err, "Rego should be there")

	_, err = os.Stat(filepath.Join(tempDir, "data.json"))
	assert.NoError(t, err, "Rego should be there")
}

func getTestBundle(path string) ([]byte, error) {
	tar, _ := compressionsupport.TarFromPath(path)

	var output []byte
	writer := bytes.NewBuffer(output)
	err := compressionsupport.Gzip(writer, tar)

	return writer.Bytes(), err
}

func initTestBundlesDir(t *testing.T) string {
	tempDir, err := os.MkdirTemp("", "authzen-*")
	assert.NoError(t, err, "No error creating tempdir")

	bundlePath := filepath.Join(tempDir, "bundle")
	err = os.Mkdir(bundlePath, 0777)
	assert.NoError(t, err, "No error creating bundle dir")

	bundle, err := getTestBundle("./test/testBundle")
	gzip, err := compressionsupport.UnGzip(bytes.NewReader(bundle))
	err = compressionsupport.UnTarToPath(bytes.NewReader(gzip), bundlePath)

	return tempDir
}

func TestUploadBundle(t *testing.T) {
	bundleDir := initTestBundlesDir(t)
	defer cleanup(bundleDir)

	_ = os.Setenv(config.EnvBundleDir, bundleDir)
	az := AuthZenApp{bundleDir: bundleDir}
	az.Decision = decisionHandler.NewDecisionHandler()

	req, err := prepareRequest("./test/testBundle")
	assert.NoError(t, err, "No error creating request")
	rr := httptest.NewRecorder()

	az.BundleUpload(rr, req)
	assert.Equal(t, http.StatusCreated, rr.Code)

}

func prepareRequest(path string) (*http.Request, error) {
	testBundle, _ := getTestBundle(path)

	buf := new(bytes.Buffer)
	writer := multipart.NewWriter(buf)
	formFile, _ := writer.CreateFormFile("bundle", "bundle.tar.gz")
	_, _ = formFile.Write(testBundle)
	_ = writer.Close()

	req, err := http.NewRequest("POST", config.EndpointOpaBundles, buf)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", writer.FormDataContentType())
	req.Header.Add("Content-Length", strconv.Itoa(buf.Len()))

	return req, err

}

func TestUploadBadBundle(t *testing.T) {
	bundleDir := initTestBundlesDir(t)
	defer cleanup(bundleDir)

	_ = os.Setenv(config.EnvBundleDir, bundleDir)
	az := AuthZenApp{bundleDir: bundleDir}
	az.Decision = decisionHandler.NewDecisionHandler()

	req, err := prepareRequest("./test/badRegoBundle")
	assert.NoError(t, err, "No error creating request")
	rr := httptest.NewRecorder()

	az.BundleUpload(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, "rego_parse_error", "Check error reported")

	req, err = prepareRequest("./test/badDataBundle")
	assert.NoError(t, err, "No error creating request")
	rr = httptest.NewRecorder()

	az.BundleUpload(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	body = rr.Body.String()
	assert.Contains(t, body, "data.json: unexpected EOF", "Check error reported")
}

func TestHandleEvaluation(t *testing.T) {
	bundleDir := initTestBundlesDir(t)
	defer cleanup(bundleDir)

	_ = os.Setenv(config.EnvBundleDir, bundleDir)
	_ = os.Setenv(config.EnvAuthUserPipFile, userHandler.DefaultUserPipFile)
	az := AuthZenApp{bundleDir: bundleDir}
	az.Decision = decisionHandler.NewDecisionHandler()

	body := infoModel.AuthRequest{
		Subject: infoModel.SubjectInfo{Identity: "CiRmZDM2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"},
		Action:  infoModel.ActionInfo{Name: "can_read_todos"},
	}

	bodyBytes, err := json.Marshal(&body)
	assert.NoError(t, err, "Check no error serializing request")
	req, err := http.NewRequest("POST", config.EndpointAuthzenSingleDecision, bytes.NewReader(bodyBytes))
	req.Header.Set(config.HeaderRequestId, "1234")
	rr := httptest.NewRecorder()
	az.HandleEvaluation(rr, req)

	assert.Equal(t, "1234", rr.Header().Get(config.HeaderRequestId), "Check request id is returned")
	assert.Equal(t, http.StatusOK, rr.Code, "Request processed ok")
	bodyBytes = rr.Body.Bytes()

	var simpleResponse infoModel.SimpleResponse
	err = json.Unmarshal(bodyBytes, &simpleResponse)
	assert.NoError(t, err, "response was parsed")
	assert.True(t, simpleResponse.Decision, "check decision is true")
}

func TestHandleQueryEvaluation(t *testing.T) {
	bundleDir := initTestBundlesDir(t)
	defer cleanup(bundleDir)

	_ = os.Setenv(config.EnvBundleDir, bundleDir)
	_ = os.Setenv(config.EnvAuthUserPipFile, userHandler.DefaultUserPipFile)
	az := AuthZenApp{bundleDir: bundleDir}
	az.Decision = decisionHandler.NewDecisionHandler()

	body := infoModel.QueryRequest{
		Subject: infoModel.SubjectInfo{Identity: "CiRmZDM2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"},
		Queries: []infoModel.QueryItem{{
			Action: "can_update_todo",
		}},
	}

	bodyBytes, err := json.Marshal(&body)
	assert.NoError(t, err, "Check no error serializing request")
	req, err := http.NewRequest("POST", config.EndpointAuthzenQuery, bytes.NewReader(bodyBytes))
	req.Header.Set(config.HeaderRequestId, "1234")
	rr := httptest.NewRecorder()
	az.HandleQueryEvaluation(rr, req)

	assert.Equal(t, "1234", rr.Header().Get(config.HeaderRequestId), "Check request id is returned")
	assert.Equal(t, http.StatusNotImplemented, rr.Code, "Request processed ok")

}

func TestHandleSecurity(t *testing.T) {
	bundleDir := initTestBundlesDir(t)
	defer cleanup(bundleDir)

	tokenHandler, err := tokensupport.GenerateIssuer("authzen", filepath.Join(bundleDir, "certs", tokensupport.DefTknPrivFileName))

	authToken, err := tokenHandler.IssueToken([]string{tokensupport.ScopeDecision}, "handlers@hexa.org")
	assert.NoError(t, err, "No error generating token")

	_ = os.Setenv(config.EnvBundleDir, bundleDir)
	_ = os.Setenv(config.EnvAuthUserPipFile, userHandler.DefaultUserPipFile)
	az := AuthZenApp{bundleDir: bundleDir}
	az.Decision = decisionHandler.NewDecisionHandler()
	az.TokenValidator = tokenHandler

	body := infoModel.AuthRequest{
		Subject: infoModel.SubjectInfo{Identity: "CiRmZDM2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"},
		Action:  infoModel.ActionInfo{Name: "can_read_todos"},
	}

	bodyBytes, err := json.Marshal(&body)
	assert.NoError(t, err, "Check no error serializing request")
	req, err := http.NewRequest("POST", config.EndpointAuthzenSingleDecision, bytes.NewReader(bodyBytes))
	req.Header.Set(config.HeaderRequestId, "1234")
	req.Header.Set("Authorization", "Bearer "+authToken)
	rr := httptest.NewRecorder()
	az.HandleEvaluation(rr, req)

	assert.Equal(t, "1234", rr.Header().Get(config.HeaderRequestId), "Check request id is returned")
	assert.Equal(t, http.StatusOK, rr.Code, "Request processed ok")
	bodyBytes = rr.Body.Bytes()

	var simpleResponse infoModel.SimpleResponse
	err = json.Unmarshal(bodyBytes, &simpleResponse)
	assert.NoError(t, err, "response was parsed")
	assert.True(t, simpleResponse.Decision, "check decision is ture")

	req.Header.Del("Authorization")
	rr = httptest.NewRecorder()
	az.HandleEvaluation(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code, "Request is unauthorized")

	req, err = http.NewRequest("GET", config.EndpointGetOpaBundles, nil)
	req.Header.Set("Authorization", "Bearer "+authToken)
	rr = httptest.NewRecorder()
	az.BundleDownload(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code, "Check request is forbidden")
}

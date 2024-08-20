package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"mime/multipart"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/hexa-org/policy-mapper/pkg/healthsupport"
	"github.com/hexa-org/policy-mapper/pkg/keysupport"
	"github.com/hexa-org/policy-mapper/pkg/oauth2support"
	"github.com/hexa-org/policy-mapper/pkg/tokensupport"
	"github.com/hexa-org/policy-mapper/pkg/websupport"
	"github.com/hexa-org/policy-opa/pkg/bundleTestSupport"
	"github.com/hexa-org/policy-opa/pkg/compressionsupport"
	"github.com/stretchr/testify/assert"
)

func TestNewApp(t *testing.T) {
	t.Setenv("PORT", "0")
	t.Setenv("HOST", "localhost")
	// _, file, _, _ := runtime.Caller(0)

	// t.Setenv(keysupport.EnvCertDirectory, filepath.Join(file, "../test/"))
	newApp("localhost:0")
}

func setup(jwtMode bool) (*http.Server, *http.Client, error) {
	listener, _ := net.Listen("tcp", "localhost:0")

	bundleDir := os.Getenv(EnvBundleDir)
	if jwtMode {
		_ = os.Setenv(tokensupport.EnvTknEnforceMode, tokensupport.ModeEnforceAll)
		_ = os.Setenv(oauth2support.EnvJwtAuth, "true")
	} else {
		_ = os.Setenv(oauth2support.EnvJwtAuth, "false")
		_ = os.Setenv(tokensupport.EnvTknEnforceMode, tokensupport.ModeEnforceAnonymous)
	}
	_ = os.Setenv(websupport.EnvTlsEnabled, "true")

	app := App(listener.Addr().String(), bundleDir)
	go func() {
		websupport.Start(app, listener)
	}()
	client := &http.Client{}
	certpath := os.Getenv(keysupport.EnvCertCaPubKey)
	fmt.Println("certpath:", certpath)

	keysupport.CheckCaInstalled(client)

	err := healthsupport.WaitForHealthyWithClient(app, client, fmt.Sprintf("https://%s/health", app.Addr))

	return app, client, err
}

func TestApp(t *testing.T) {
	app, client, err := setup(false)
	assert.NoError(t, err)
	response, _ := client.Get(fmt.Sprintf("https://%s/health", app.Addr))
	assert.Equal(t, http.StatusOK, response.StatusCode)
	websupport.Stop(app)
}

func TestDownload(t *testing.T) {
	app, client, err := setup(false)
	assert.NoError(t, err)
	response, err := client.Get(fmt.Sprintf("https://%s/bundles/bundle.tar.gz", app.Addr))
	assert.NoError(t, err, "Should be no error on get")
	assert.Equal(t, http.StatusOK, response.StatusCode)
	websupport.Stop(app)
}

func TestDownloadAuth(t *testing.T) {
	app, client, _ := setup(true)

	// Unauthorized request
	reqUrl := fmt.Sprintf("https://%s/bundles/bundle.tar.gz", app.Addr)
	response, err := client.Get(reqUrl)
	assert.NoError(t, err, "Should be no error on request")
	assert.Equal(t, http.StatusUnauthorized, response.StatusCode)

	req, _ := http.NewRequest(http.MethodGet, reqUrl, nil)
	req.Header.Set("Authorization", "Bearer "+bundleToken)

	resp, err := client.Do(req)
	assert.NoError(t, err, "Request completed with no error")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Wrong scope
	req.Header.Set("Authorization", "Bearer "+badToken)

	resp, err = client.Do(req)
	assert.NoError(t, err, "Request completed with no error")
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	websupport.Stop(app)
}

func TestUpload(t *testing.T) {
	app, client, err := setup(false)
	assert.NoError(t, err)
	_, file, _, _ := runtime.Caller(0)
	bundleDir := filepath.Join(file, "../resources/bundles")
	tar, _ := compressionsupport.TarFromPath(bundleDir)
	var buffer bytes.Buffer
	_ = compressionsupport.Gzip(&buffer, tar)

	buf := new(bytes.Buffer)
	writer := multipart.NewWriter(buf)
	formFile, _ := writer.CreateFormFile("bundle", "bundle.tar.gz")
	_, _ = formFile.Write(buffer.Bytes())
	_ = writer.Close()

	// test to /bundles
	contentType := writer.FormDataContentType()
	response, _ := client.Post(fmt.Sprintf("https://%s/bundles", app.Addr), contentType, buf)
	assert.Equal(t, http.StatusCreated, response.StatusCode)

	// repeat test to /bundles/bundle.tar.gz  (sdk uses this)
	buf = new(bytes.Buffer)
	writer = multipart.NewWriter(buf)
	_ = compressionsupport.Gzip(&buffer, tar)
	formFile, _ = writer.CreateFormFile("bundle", "bundle.tar.gz")
	_, _ = formFile.Write(buffer.Bytes())
	_ = writer.Close()
	contentType = writer.FormDataContentType()

	response2, _ := client.Post(fmt.Sprintf("https://%s/bundles/bundle.tar.gz", app.Addr), contentType, buf)
	assert.Equal(t, http.StatusCreated, response2.StatusCode)

	_, _ = client.Get(fmt.Sprintf("http://%s/reset", app.Addr))
	websupport.Stop(app)
}

func TestReset(t *testing.T) {
	app, client, err := setup(false)
	assert.NoError(t, err)
	response, _ := client.Get(fmt.Sprintf("https://%s/reset", app.Addr))
	assert.Equal(t, http.StatusOK, response.StatusCode)
	websupport.Stop(app)
}

func TestResetAuth(t *testing.T) {
	app, client, err := setup(true)
	assert.NoError(t, err)

	reqUrl := fmt.Sprintf("https://%s/reset", app.Addr)
	response, _ := client.Get(reqUrl)

	assert.Equal(t, http.StatusUnauthorized, response.StatusCode)

	req, _ := http.NewRequest(http.MethodGet, reqUrl, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := client.Do(req)
	assert.NoError(t, err, "Request completed with no error")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	websupport.Stop(app)
}

// Test_EmptyBundleDir simulates what happens with HexaBundleServer starts in docker (with an empty bundles directory)
func Test_EmptyBundleDir(t *testing.T) {
	bundleDir := bundleTestSupport.InitTestEmptyBundleDir(t)
	defer bundleTestSupport.Cleanup(bundleDir)
	saveDir := os.Getenv(EnvBundleDir)
	_ = os.Setenv(EnvBundleDir, bundleDir)

	app, client, err := setup(false)
	assert.NoError(t, err)

	response, _ := client.Get(fmt.Sprintf("https://%s/health", app.Addr))
	assert.Equal(t, http.StatusOK, response.StatusCode)

	dataFilePath := filepath.Join(bundleDir, "bundle", "data.json")
	dataBytes, err := os.ReadFile(dataFilePath)
	assert.NoError(t, err, "Data file should exist!")
	assert.Equal(t, hexaPolicyBytes, dataBytes, "Check the file created was the default policy")

	manifestPath := filepath.Join(bundleDir, "bundle", ".manifest")
	manifestBytes, err := os.ReadFile(manifestPath)
	assert.NoError(t, err, "Manifest file should exist!")
	assert.Greater(t, len(manifestBytes), 10, "Manifest should have a few bytes")

	regoPath := filepath.Join(bundleDir, "bundle", "hexaPolicy.rego")
	regoBytes, err := os.ReadFile(regoPath)
	assert.NoError(t, err, "Manifest file should exist!")
	assert.Greater(t, len(regoBytes), 100, "Rego should have > 100 bytes")

	websupport.Stop(app)

	_ = os.Setenv(EnvBundleDir, saveDir)
}

func TestZZNewAppWithTransportLayerSecurity(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	t.Setenv(keysupport.EnvServerCert, filepath.Join(file, "../test/server-cert.pem"))
	t.Setenv(keysupport.EnvServerKey, filepath.Join(file, "../test/server-key.pem"))
	t.Setenv(keysupport.EnvCertDirectory, filepath.Join(file, "../test/"))
	app, listener := newApp("localhost:0")

	go func() {
		websupport.Start(app, listener)
	}()
	defer websupport.Stop(app)

	caCert := must(os.ReadFile(filepath.Join(file, "../test/ca-cert.pem")))
	clientCert, _ := tls.X509KeyPair(
		must(os.ReadFile(filepath.Join(file, "../test/client-cert.pem"))),
		must(os.ReadFile(filepath.Join(file, "../test/client-key.pem"))),
	)
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	client := &http.Client{
		Timeout: time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{clientCert},
				RootCAs:      caCertPool,
			},
		},
	}
	healthsupport.WaitForHealthyWithClient(
		app,
		client,
		fmt.Sprintf("https://%s/health", app.Addr),
	)
}

func TestZZNewAppWithTLS_PanicsWithBadServerCertPath(t *testing.T) {
	// Should not panic as long as the private key is available
	_, file, _, _ := runtime.Caller(0)
	t.Setenv(keysupport.EnvServerCert, "/do-not-exist")
	t.Setenv(keysupport.EnvServerKey, filepath.Join(file, "../test/server-key.pem"))
	t.Setenv(keysupport.EnvAutoCreate, "false")

	assert.Panics(t, func() { newApp("localhost:0") })
}

func TestZZNewAppWithTLS_PanicsWithBadServerKeyPath(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	t.Setenv(keysupport.EnvServerCert, filepath.Join(file, "../test/server-cert.pem"))
	t.Setenv(keysupport.EnvServerKey, "/do-not-exist")
	t.Setenv(keysupport.EnvAutoCreate, "false")

	assert.Panics(t, func() { newApp("localhost:0") })
}

func TestZZNewAppWithTLS_PanicsWithBadPair(t *testing.T) {
	tmp := t.TempDir()

	certFile := filepath.Join(tmp, fmt.Sprintf("%s-cert.pem", t.Name()))
	keyFile := filepath.Join(tmp, fmt.Sprintf("%s-key.pem", t.Name()))
	assert.NoError(t, os.WriteFile(
		certFile,
		[]byte("not a cert"),
		0644,
	))
	assert.NoError(t, os.WriteFile(
		keyFile,
		[]byte("not a key"),
		0644,
	))

	t.Setenv("HEXA_SERVER_CERT", certFile)
	t.Setenv("HEXA_SERVER_KEY_PATH", keyFile)

	assert.Panics(t, func() { newApp("localhost:0") })
}

func must(file []byte, err error) []byte {
	if err != nil {
		panic(fmt.Sprintf("unable to read file: %s", err))
	}
	return file
}

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

	"github.com/hexa-org/policy-opa/pkg/compressionsupport"
	"github.com/hexa-org/policy-opa/pkg/healthsupport"
	"github.com/hexa-org/policy-opa/pkg/keysupport"
	"github.com/hexa-org/policy-opa/pkg/tokensupport"
	"github.com/hexa-org/policy-opa/pkg/websupport"
	"github.com/stretchr/testify/assert"
)

func TestNewApp(t *testing.T) {
	t.Setenv("PORT", "0")
	t.Setenv("HOST", "localhost")
	_, file, _, _ := runtime.Caller(0)

	t.Setenv(keysupport.EnvCertDirectory, filepath.Join(file, "../test/"))
	newApp("localhost:0", DEF_TEST_BUNDLE_PATH)
}

func setup(jwtMode bool) *http.Server {
	listener, _ := net.Listen("tcp", "localhost:0")
	_, file, _, _ := runtime.Caller(0)
	bundleDir := filepath.Join(file, DEF_TEST_BUNDLE_PATH)
	if jwtMode {
		_ = os.Setenv(tokensupport.EnvTknEnforceMode, tokensupport.ModeEnforceAll)

	} else {
		_ = os.Setenv(tokensupport.EnvTknEnforceMode, tokensupport.ModeEnforceAnonymous)
	}
	app := App(listener.Addr().String(), bundleDir)
	go func() {
		websupport.Start(app, listener)
	}()
	healthsupport.WaitForHealthy(app)
	return app
}

func TestApp(t *testing.T) {
	app := setup(false)
	response, _ := http.Get(fmt.Sprintf("http://%s/health", app.Addr))
	assert.Equal(t, http.StatusOK, response.StatusCode)
	websupport.Stop(app)
}

func TestDownload(t *testing.T) {
	app := setup(false)
	response, _ := http.Get(fmt.Sprintf("http://%s/bundles/bundle.tar.gz", app.Addr))
	assert.Equal(t, http.StatusOK, response.StatusCode)
	websupport.Stop(app)
}

func TestDownloadAuth(t *testing.T) {
	app := setup(true)

	// Unauthorized request
	reqUrl := fmt.Sprintf("http://%s/bundles/bundle.tar.gz", app.Addr)
	response, _ := http.Get(reqUrl)
	assert.Equal(t, http.StatusUnauthorized, response.StatusCode)

	req, _ := http.NewRequest(http.MethodGet, reqUrl, nil)
	req.Header.Set("Authorization", "Bearer "+bundleToken)
	client := http.Client{}
	defer client.CloseIdleConnections()

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
	app := setup(false)

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

	contentType := writer.FormDataContentType()
	response, _ := http.Post(fmt.Sprintf("http://%s/bundles", app.Addr), contentType, buf)
	assert.Equal(t, http.StatusCreated, response.StatusCode)

	_, _ = http.Get(fmt.Sprintf("http://%s/reset", app.Addr))
	websupport.Stop(app)
}

func TestReset(t *testing.T) {
	app := setup(false)
	response, _ := http.Get(fmt.Sprintf("http://%s/reset", app.Addr))
	assert.Equal(t, http.StatusOK, response.StatusCode)
	websupport.Stop(app)
}

func TestResetAuth(t *testing.T) {
	app := setup(true)

	reqUrl := fmt.Sprintf("http://%s/reset", app.Addr)
	response, _ := http.Get(reqUrl)

	assert.Equal(t, http.StatusUnauthorized, response.StatusCode)

	req, _ := http.NewRequest(http.MethodGet, reqUrl, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	client := http.Client{}
	defer client.CloseIdleConnections()

	resp, err := client.Do(req)
	assert.NoError(t, err, "Request completed with no error")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	websupport.Stop(app)
}

func TestNewAppWithTransportLayerSecurity(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	t.Setenv("SERVER_CERT", filepath.Join(file, "../test/server-cert.pem"))
	t.Setenv("SERVER_KEY", filepath.Join(file, "../test/server-EnvBundleDir.pem"))
	t.Setenv(keysupport.EnvCertDirectory, filepath.Join(file, "../test/"))
	app, listener := newApp("localhost:0", DEF_TEST_BUNDLE_PATH)

	go func() {
		websupport.Start(app, listener)
	}()
	defer websupport.Stop(app)

	caCert := must(os.ReadFile(filepath.Join(file, "../test/ca-cert.pem")))
	clientCert, _ := tls.X509KeyPair(
		must(os.ReadFile(filepath.Join(file, "../test/client-cert.pem"))),
		must(os.ReadFile(filepath.Join(file, "../test/client-EnvBundleDir.pem"))),
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

func TestNewAppWithTLS_PanicsWithBadServerCertPath(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	t.Setenv("SERVER_CERT", "/do-not-exist")
	t.Setenv("SERVER_KEY", filepath.Join(file, "../test/server-EnvBundleDir.pem"))

	assert.Panics(t, func() { newApp("localhost:0", DEF_TEST_BUNDLE_PATH) })
}

func TestNewAppWithTLS_PanicsWithBadServerKeyPath(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	t.Setenv("SERVER_CERT", filepath.Join(file, "../test/server-cert.pem"))
	t.Setenv("SERVER_KEY", "/do-not-exist")

	assert.Panics(t, func() { newApp("localhost:0", DEF_TEST_BUNDLE_PATH) })
}

func TestNewAppWithTLS_PanicsWithBadPair(t *testing.T) {
	tmp := t.TempDir()

	certFile := filepath.Join(tmp, fmt.Sprintf("%s-cert.pem", t.Name()))
	keyFile := filepath.Join(tmp, fmt.Sprintf("%s-EnvBundleDir.pem", t.Name()))
	assert.NoError(t, os.WriteFile(
		certFile,
		[]byte("not a cert"),
		0644,
	))
	assert.NoError(t, os.WriteFile(
		keyFile,
		[]byte("not a EnvBundleDir"),
		0644,
	))

	t.Setenv("SERVER_CERT", certFile)
	t.Setenv("SERVER_KEY", keyFile)

	assert.Panics(t, func() { newApp("localhost:0", DEF_TEST_BUNDLE_PATH) })
}

func must(file []byte, err error) []byte {
	if err != nil {
		panic(fmt.Sprintf("unable to read file: %s", err))
	}
	return file
}
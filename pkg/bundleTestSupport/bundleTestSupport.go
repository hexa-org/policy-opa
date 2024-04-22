package bundleTestSupport

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/config"
	"github.com/hexa-org/policy-opa/pkg/compressionsupport"
	"github.com/stretchr/testify/assert"
)

func Cleanup(path string) {
	_ = os.RemoveAll(path)
}

func GetTestBundle(path string) ([]byte, error) {
	tar, _ := compressionsupport.TarFromPath(path)

	var output []byte
	writer := bytes.NewBuffer(output)
	err := compressionsupport.Gzip(writer, tar)

	return writer.Bytes(), err
}

func GetTestBundlePath(bundle string) string {
	_, file, _, _ := runtime.Caller(0)

	return filepath.Join(path.Dir(file), bundle)
}

func InitTestBundlesDir(t *testing.T) string {
	tempDir, err := os.MkdirTemp("", "authzen-*")
	assert.NoError(t, err, "No error creating tempdir")

	bundlePath := GetTestBundlePath("./test/testBundle")
	bundle, err := GetTestBundle(bundlePath)
	gzip, err := compressionsupport.UnGzip(bytes.NewReader(bundle))

	err = compressionsupport.UnTarToPath(bytes.NewReader(gzip), tempDir)

	return tempDir
}

func PrepareBundleUploadRequest(path string) (*http.Request, error) {
	testBundle, _ := GetTestBundle(path)

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

package keysupport

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/hexa-org/policy-opa/pkg/websupport"
	"github.com/stretchr/testify/assert"
)

var dirTest1 string

func TestDefaultMode(t *testing.T) {

	var err error
	dirTest1, err = os.MkdirTemp("", "certs-*")
	assert.Nil(t, err, "Should be no error on temp dir create")

	t.Setenv(EnvCertDirectory, dirTest1)
	t.Setenv(EnvCertCaPubKey, "")
	t.Setenv(EnvCertCaPrivKey, "")
	t.Setenv(EnvServerCert, "")
	t.Setenv(EnvServerKey, "")
	t.Setenv(EnvServerDNS, "hexaOrchestrator")

	config := GetKeyConfig()

	assert.Equal(t, dirTest1, config.CertDir)

	assert.Equal(t, filepath.Join(dirTest1, "ca-key.pem"), config.CaKeyFile)
	assert.Equal(t, filepath.Join(dirTest1, "server-key.pem"), config.ServerKeyPath)
	assert.Equal(t, []string{"Hexa Organization"}, config.PkixName.Organization)

	assert.False(t, config.RootKeyExists())
	assert.False(t, config.ServerCertExists())

	err = config.InitializeKeys()
	assert.Nil(t, err, "No error generating keys")

	keyBytes, err := os.ReadFile(config.CaKeyFile)
	assert.Nil(t, err, "No error reading server key")
	assert.Greater(t, len(keyBytes), 100, "Key file is greater than 100 bytes")

	pemBlock, rest := pem.Decode(keyBytes)
	assert.Equal(t, 0, len(rest), "Should be no extra in pem decode")
	assert.NotNil(t, pemBlock, "pem was decoded")

	assert.True(t, config.RootKeyExists())
	assert.True(t, config.ServerCertExists())
	_, err = x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	assert.Nil(t, err, "No error parsing key")

	err = checkCertDns(config.ServerCertPath, "hexaOrchestrator")
	assert.NoError(t, err, "Check DNS match")
}

/*
TestExistKey starts the server with a new key directory but allows ca keys from another directory
*/
func TestExistKey(t *testing.T) {
	dir, err := os.MkdirTemp("", "certs-*")
	assert.Nil(t, err, "Should be no error on temp dir create")
	defer os.RemoveAll(dir)

	t.Setenv(EnvCertDirectory, dir)
	t.Setenv(EnvCertCaPubKey, filepath.Join(dirTest1, "ca-cert.pem"))
	t.Setenv(EnvCertCaPrivKey, filepath.Join(dirTest1, "ca-key.pem"))
	t.Setenv(EnvServerDNS, "hexaBundleServer")
	t.Setenv(EnvServerCert, "")              // create the default file
	t.Setenv(EnvServerKey, "server-key.pem") // check it is placed in certdir

	config := GetKeyConfig()

	assert.Equal(t, dir, config.CertDir)

	assert.Equal(t, filepath.Join(dirTest1, "ca-key.pem"), config.CaKeyFile)
	assert.Equal(t, filepath.Join(dir, "server-key.pem"), config.ServerKeyPath)
	assert.Equal(t, []string{"Hexa Organization"}, config.PkixName.Organization)

	assert.True(t, config.RootKeyExists())
	assert.False(t, config.ServerCertExists())

	err = config.InitializeKeys()
	assert.Nil(t, err, "No error generating keys")

	keyBytes, err := os.ReadFile(config.ServerKeyPath)
	assert.Nil(t, err, "No error reading server key")
	assert.Greater(t, len(keyBytes), 100, "Key file is greater than 100 bytes")

	pemBlock, rest := pem.Decode(keyBytes)
	assert.Equal(t, 0, len(rest), "Should be no extra in pem decode")
	assert.NotNil(t, pemBlock, "pem was decoded")

	_, err = x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	assert.Nil(t, err, "No error parsing key")

	assert.True(t, config.RootKeyExists()) // because it is in a different directory
	assert.True(t, config.ServerCertExists())

	// should not exist in new directory
	_, err = os.ReadFile(filepath.Join(config.CertDir, "ca-key.pem"))
	assert.True(t, os.IsNotExist(err), "ca-key should not exist in the certs directory")
	err = checkCertDns(config.ServerCertPath, "hexabundleserver")
	assert.NoError(t, err, "Check DNS match")
}

// TestAnotherServer checks that more than one server can share the same certificate directory (shared CA key)
func TestAnotherServer(t *testing.T) {
	defer os.RemoveAll(dirTest1)
	t.Setenv(EnvCertDirectory, dirTest1)
	t.Setenv(EnvCertCaPubKey, filepath.Join(dirTest1, "ca-cert.pem"))
	t.Setenv(EnvCertCaPrivKey, filepath.Join(dirTest1, "ca-key.pem"))
	t.Setenv(EnvServerCert, "server-another-cert.pem") // this one should test defaulting to certDir
	t.Setenv(EnvServerKey, filepath.Join(dirTest1, "server-another-key.pem"))
	t.Setenv(EnvServerDNS, "anotherServer")

	config := GetKeyConfig()
	assert.Equal(t, dirTest1, config.CertDir)

	assert.Equal(t, filepath.Join(dirTest1, "ca-key.pem"), config.CaKeyFile)
	assert.Equal(t, filepath.Join(dirTest1, "server-another-key.pem"), config.ServerKeyPath)
	assert.Equal(t, filepath.Join(dirTest1, "server-another-cert.pem"), config.ServerCertPath)
	assert.Equal(t, []string{"Hexa Organization"}, config.PkixName.Organization)

	assert.True(t, config.RootKeyExists())
	assert.False(t, config.ServerCertExists())

	err := config.InitializeKeys()
	assert.Nil(t, err, "No error generating keys")

	assert.Equal(t, filepath.Join(dirTest1, "server-another-key.pem"), config.ServerKeyPath, "Check keypath has not changed")

	keyBytes, err := os.ReadFile(config.ServerKeyPath)
	assert.Nil(t, err, "No error reading server key")
	assert.Greater(t, len(keyBytes), 100, "Key file is greater than 100 bytes")

	err = checkCertDns(config.ServerCertPath, "Anotherserver")
	assert.NoError(t, err, "Check DNS match")

}

// checkCertDns verifies that the certificate referenced has the expected DNS name
func checkCertDns(path string, dnsname string) error {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	derBlock, _ := pem.Decode(pemBytes)

	cert, err := x509.ParseCertificate(derBlock.Bytes)

	names := cert.DNSNames
	if names != nil {
		for _, name := range names {
			if strings.EqualFold(name, dnsname) {
				return nil
			}
		}
	}

	return errors.New("dns name not matched")
}

func TestCheckCaInstalled(t *testing.T) {

	var err error
	dirTest, err := os.MkdirTemp("", "certs-*")
	assert.Nil(t, err, "Should be no error on temp dir create")
	defer os.RemoveAll(dirTest)

	t.Setenv(EnvCertDirectory, dirTest)
	t.Setenv(EnvCertCaPubKey, "")
	t.Setenv(EnvCertCaPrivKey, "")
	t.Setenv(EnvServerCert, "")
	t.Setenv(EnvServerKey, "")
	t.Setenv(EnvServerDNS, "hexaOrchestrator")

	config := GetKeyConfig()
	err = config.InitializeKeys()
	assert.Nil(t, err, "No error generating keys")
	server := startTestServer(&config)

	t.Setenv(EnvCertCaPubKey, config.CaCertFile)
	client := http.Client{}
	CheckCaInstalled(&client)
	time.Sleep(time.Millisecond * 10)
	resp, err := client.Get(fmt.Sprintf("https://%s/health", server.Addr))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	dnsnames := resp.TLS.PeerCertificates[0].DNSNames
	assert.Equal(t, "hexaOrchestrator", dnsnames[0])
	client.CloseIdleConnections()
	websupport.Stop(server)
}

func startTestServer(keyconfig *KeyConfig) *http.Server {
	listener, _ := net.Listen("tcp", "localhost:0")
	server := websupport.Create(listener.Addr().String(), func(x *mux.Router) {}, websupport.Options{})
	websupport.WithTransportLayerSecurity(keyconfig.ServerCertPath, keyconfig.ServerKeyPath, server)
	go websupport.Start(server, listener)
	return server
}

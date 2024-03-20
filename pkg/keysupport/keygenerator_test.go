package keysupport

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

var dirTest1 string

func TestDefaultMode(t *testing.T) {

	var err error
	dirTest1, err = os.MkdirTemp("", "certs-*")
	assert.Nil(t, err, "Should be no error on temp dir create")

	t.Setenv(EnvCertDirectory, dirTest1)
	t.Setenv(EnvCertCaKey, "")
	t.Setenv(EnvServerCert, "")
	t.Setenv(EnvServerKey, "")

	config := GetKeyConfig()

	assert.Equal(t, dirTest1, config.CertDir)

	assert.Equal(t, filepath.Join(dirTest1, "ca-key.pem"), config.KeyFile)
	assert.Equal(t, filepath.Join(dirTest1, "server-key.pem"), config.ServerKeyPath)
	assert.Equal(t, []string{"Hexa Organization"}, config.PkixName.Organization)

	assert.False(t, config.RootKeyExists())
	assert.False(t, config.ServerKeyExists())

	err = config.CreateSelfSignedKeys()
	assert.Nil(t, err, "No error generating keys")

	keyBytes, err := os.ReadFile(config.KeyFile)
	assert.Nil(t, err, "No error reading server key")
	assert.Greater(t, len(keyBytes), 100, "Key file is greater than 100 bytes")

	pemBlock, rest := pem.Decode(keyBytes)
	assert.Equal(t, 0, len(rest), "Should be no extra in pem decode")
	assert.NotNil(t, pemBlock, "pem was decoded")

	assert.True(t, config.RootKeyExists())
	assert.True(t, config.ServerKeyExists())
	_, err = x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	assert.Nil(t, err, "No error parsing key")
}

/*
TestExistKey uses the key from the previous test but creates keys in a new directory
*/
func TestExistKey(t *testing.T) {
	dir, err := os.MkdirTemp("", "certs-*")
	assert.Nil(t, err, "Should be no error on temp dir create")
	defer os.RemoveAll(dir)
	defer os.RemoveAll(dirTest1)

	t.Setenv(EnvCertDirectory, dir)
	t.Setenv(EnvCertCaKey, filepath.Join(dirTest1, "ca-key.pem"))
	t.Setenv(EnvServerCert, "")
	t.Setenv(EnvServerKey, "")

	config := GetKeyConfig()

	assert.Equal(t, dir, config.CertDir)

	assert.Equal(t, filepath.Join(dirTest1, "ca-key.pem"), config.KeyFile)
	assert.Equal(t, filepath.Join(dir, "server-key.pem"), config.ServerKeyPath)
	assert.Equal(t, []string{"Hexa Organization"}, config.PkixName.Organization)

	assert.True(t, config.RootKeyExists())
	assert.False(t, config.ServerKeyExists())

	err = config.CreateSelfSignedKeys()
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
	assert.True(t, config.ServerKeyExists())

	// should not exist in new directory
	_, err = os.ReadFile(filepath.Join(config.CertDir, "ca-key.pem"))
	assert.True(t, os.IsNotExist(err), "ca-key should not exist in the certs directory")
}

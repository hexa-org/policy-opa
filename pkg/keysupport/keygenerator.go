/*
Package keysupport is used to generate self-signed keys for testing purposes.

This code was pulled and modified from the following resources:
- https://gist.github.com/shaneutt/5e1995295cff6721c89a71d13a71c251
- https://shaneutt.com/blog/golang-ca-and-signed-cert-go/.

USAGE:

Use the genKeys command to call this routine.

	go run cmd/genKeys

This will generate a CA cert/key pair and use that to sign Server cert/key pair
and Client cert/key pair.

Use these certs for tests such as websupport_test and orchestrator_test.
*/
package keysupport

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	EnvCertOrg       string = "HEXA_CERT_ORG"
	EnvCertCountry   string = "HEXA_CERT_COUNTRY"
	EnvCertProv      string = "HEXA_CERT_PROV"
	EnvCertLocality  string = "HEXA_CERT_LOCALITY"
	EnvCertCaKey     string = "HEXA_CA_KEYFILE"     // The location of a private key used to generate server keys
	EnvCertDirectory string = "HEXA_CERT_DIRECTORY" // The location where keys are stored.
	EnvServerCert    string = "SERVER_CERT"
	EnvServerKey     string = "SERVER_KEY_PATH"
	EnvAutoCreate    string = "HEXA_AUTO_SELFSIGN"
)

type KeyConfig struct {
	KeyFile        string // The file containing a PEM encoded PKCS1 private key
	CertDir        string // This is the directory where generated keys are output
	PkixName       pkix.Name
	ServerCertPath string
	ServerKeyPath  string
}

/*
GetKeyConfig reads environment variables and sets up configuration parameters in KeyConfig struct.  Note that if
no environment variables are set, the default directory is the current directory plus "./.certs".  When running in
docker-compose as a minimum, HEXA_CERT_DIRECTORY should be set.
*/
func GetKeyConfig() KeyConfig {
	org := os.Getenv(EnvCertOrg)
	if org == "" {
		org = "Hexa Organization"
	}
	country := os.Getenv(EnvCertCountry)
	if country == "" {
		country = "US"
	}
	prov := os.Getenv(EnvCertProv)
	if prov == "" {
		prov = "CO"
	}
	locality := os.Getenv(EnvCertLocality)
	if locality == "" {
		locality = "Boulder"
	}

	certDir := os.Getenv(EnvCertDirectory)
	if certDir == "" {

		file := os.Getenv("GOPATH")
		certDir = filepath.Join(file, "./.certs")
		fmt.Println("Defaulting certificate directory to: " + certDir)
	}

	// Create the directory if it does not exist
	err := os.Mkdir(certDir, 0755)
	if !os.IsExist(err) {
		panic(fmt.Sprintf("Was unable to open or create certificate directory(%s):%s", certDir, err))
	}

	caKey := os.Getenv(EnvCertCaKey)
	if caKey == "" {
		caKey = filepath.Join(certDir, "ca-key.pem")
	}

	serverKeyPath := os.Getenv(EnvServerKey)
	if serverKeyPath == "" {
		serverKeyPath = filepath.Join(certDir, "server-key.pem")
	}

	serverCertPath := os.Getenv(EnvServerCert)
	if serverCertPath == "" {
		serverCertPath = filepath.Join(certDir, "server-cert.pem")
	}

	return KeyConfig{
		KeyFile:        caKey,
		CertDir:        certDir,
		ServerKeyPath:  serverKeyPath,
		ServerCertPath: serverCertPath,
		PkixName: pkix.Name{
			Organization: []string{org},
			Country:      []string{country},
			Province:     []string{prov},
			Locality:     []string{locality},
		},
	}
}

func (config KeyConfig) CertDirExists() bool {
	dirStat, err := os.Stat(config.CertDir)
	if err != nil {
		return false
	}
	return dirStat.IsDir()
}
func (config KeyConfig) RootKeyExists() bool {
	_, err := os.Stat(config.KeyFile)
	return err == nil
}

func (config KeyConfig) ServerKeyExists() bool {
	_, err := os.Stat(config.ServerKeyPath)
	return err == nil
}

/*
CreateSelfSignedKeys creates a set of self signed keys and writes them out to the directory in KeyConfig.CertDir
This includes:  Certificate Authority Certificate and Key (ca-cert/ca-key), Server certificate (server-cert.pem) and key
(server-key.pem), and a client certificate (client-cert.pem) and key (client-key.pem).
*/
func (config KeyConfig) CreateSelfSignedKeys() (err error) {
	auto := os.Getenv(EnvAutoCreate)
	if auto != "" && strings.ToLower(auto[0:1]) == "f" {
		log.Println("Auto self-sign create is disabled (HEXA_AUTO_SELFSIGN). Will not generate.")
		return nil
	}
	// set up our CA certificate
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(2019),
		Subject:               config.PkixName,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	var caPrivKey *rsa.PrivateKey

	keyFile := config.KeyFile
	if keyFile != "" {
		_, err := os.Stat(keyFile) // first check that it exists, otherwise fall through to create
		if err == nil {
			log.Println(fmt.Sprintf("Attempting to load existing CA Key from %s ...", keyFile))
			keyBytes, err := os.ReadFile(keyFile)
			if err != nil {
				return err
			}
			if len(keyBytes) > 10 {
				pemBlock, _ := pem.Decode(keyBytes)
				if pemBlock == nil {
					return errors.New("expecting file to contain a PEM key")
				}
				caBytes := pemBlock.Bytes
				caPrivKey, err = x509.ParsePKCS1PrivateKey(caBytes)
				if err != nil {
					return err
				}
			}
		}
	}
	if caPrivKey == nil {
		log.Println("Generating new CA key...")
		// create our private and public key
		caPrivKey, err = rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return err
		}

		caPrivKeyPEM := new(bytes.Buffer)
		_ = pem.Encode(caPrivKeyPEM, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
		})
		log.Println("Writing out CA Key")
		err = os.WriteFile(config.KeyFile, caPrivKeyPEM.Bytes(), 0644)
		if err != nil {
			return err
		}

	}

	// create the CA Public key file (in case it does not exist)
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return err
	}

	// pem encode
	caPEM := new(bytes.Buffer)
	_ = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	log.Println("Writing out CA Cert")

	err = os.WriteFile(filepath.Join(config.CertDir, "ca-cert.pem"), caPEM.Bytes(), 0644)
	if err != nil {
		return err
	}

	// set up our server certificate
	certPEM, certPrivKeyPEM, err := config.generateCert(
		ca,
		caPrivKey,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		[]string{"hexa-bundle-server"},
	)
	if err != nil {
		return err
	}
	log.Println("Writing out Server Cert")
	err = os.WriteFile(config.ServerCertPath, certPEM, 0644)
	if err != nil {
		return err
	}
	log.Println("Writing out Server Key")
	err = os.WriteFile(config.ServerKeyPath, certPrivKeyPEM, 0644)
	if err != nil {
		return err
	}

	// set up our client certificate
	clientCertPEM, clientCertPrivKeyPEM, err := config.generateCert(
		ca,
		caPrivKey,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		[]string{},
	)
	if err != nil {
		return err
	}

	log.Println("Writing out Client Cert")
	err = os.WriteFile(filepath.Join(config.CertDir, "client-cert.pem"), clientCertPEM, 0644)
	if err != nil {
		return err
	}
	log.Println("Writing out Client Key")
	err = os.WriteFile(filepath.Join(config.CertDir, "client-key.pem"), clientCertPrivKeyPEM, 0644)
	if err != nil {
		return err
	}

	return
}

func (config KeyConfig) generateCert(
	ca *x509.Certificate,
	caPrivKey *rsa.PrivateKey,
	keyUsage []x509.ExtKeyUsage,
	dnsNames []string) ([]byte, []byte, error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject:      config.PkixName,
		DNSNames:     dnsNames,
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  keyUsage,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM := new(bytes.Buffer)
	_ = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	_ = pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	return certPEM.Bytes(), certPrivKeyPEM.Bytes(), nil
}

/*
Package keysupport is used to generate self-signed keys for testing purposes.

This code was pulled and modified from the following resources:
- https://gist.github.com/shaneutt/5e1995295cff6721c89a71d13a71c251
- https://shaneutt.com/blog/golang-ca-and-signed-cert-go/.

USAGE:

Use the hexaKeyTool command to call this routine.

	go run cmd/hexaKeyTool

This will generate a CA cert/key pair and use that to sign Server cert/key pair
and Client cert/key pair.

Use these certs for tests such as websupport_test and orchestrator_test.
*/
package keysupport

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	log "golang.org/x/exp/slog"
)

const (
	EnvCertOrg       string = "HEXA_CERT_ORG"
	EnvCertCountry   string = "HEXA_CERT_COUNTRY"
	EnvCertProv      string = "HEXA_CERT_PROV"
	EnvCertLocality  string = "HEXA_CERT_LOCALITY"
	EnvCertCaPrivKey string = "HEXA_CA_KEYFILE" // The location of a private key used to generate server keys
	EnvCertCaPubKey  string = "HEXA_CA_CERT"
	EnvCertDirectory string = "HEXA_CERT_DIRECTORY" // The location where keys are stored.
	EnvServerCert    string = "HEXA_SERVER_CERT"
	EnvServerKey     string = "HEXA_SERVER_KEY_PATH"
	EnvServerDNS     string = "HEXA_SERVER_DNS_NAME"
	EnvAutoCreate    string = "HEXA_AUTO_SELFSIGN"
)

type KeyConfig struct {
	CaKeyFile      string // The file containing a PEM encoded PKCS1 private key
	CaCertFile     string
	CaPrivKey      *rsa.PrivateKey
	CertDir        string // This is the directory where generated keys are output
	PkixName       pkix.Name
	ServerCertPath string
	ServerKeyPath  string
	CaConfig       *x509.Certificate
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
		file := os.Getenv("HOME")
		certDir = filepath.Join(file, "./.certs")
		log.Info("Defaulting certificate directory to: " + certDir)
	}

	// Create the directory if it does not exist
	err := os.Mkdir(certDir, 0755)
	if !os.IsExist(err) {
		msg := fmt.Sprintf("Was unable to open or create certificate directory(%s):%s", certDir, err)
		log.Error(msg)
		panic(msg)
	}

	caCertKey := os.Getenv(EnvCertCaPrivKey)
	if caCertKey == "" {
		caCertKey = filepath.Join(certDir, "ca-key.pem")
	}

	caCert := os.Getenv(EnvCertCaPubKey)
	if caCert == "" {
		caCert = filepath.Join(certDir, "ca-cert.pem")
	}

	serverKeyPath := os.Getenv(EnvServerKey)
	if serverKeyPath == "" {
		serverKeyPath = filepath.Join(certDir, "server-key.pem")
	} else {
		if filepath.Dir(serverKeyPath) == "." {
			// if the server key path is just a file name, prefix it with certDir
			serverKeyPath = filepath.Join(certDir, serverKeyPath)
		}
	}

	serverCertPath := os.Getenv(EnvServerCert)
	if serverCertPath == "" {
		serverCertPath = filepath.Join(certDir, "server-cert.pem")
	} else {
		if filepath.Dir(serverCertPath) == "." {
			// if the server cert path is just a file name, prefix it with certDir
			serverCertPath = filepath.Join(certDir, serverCertPath)
		}
	}

	return KeyConfig{
		CaKeyFile:      caCertKey,
		CaCertFile:     caCert,
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
	_, err := os.Stat(config.CaKeyFile)
	return err == nil
}

func (config KeyConfig) ServerCertExists() bool {
	_, err := os.Stat(config.ServerCertPath)
	return err == nil
}

/*
InitializeKeys creates a set of self-signed keys and writes them out to the directory in KeyConfig.CertDir
This includes:  Certificate Authority Certificate and Key (ca-cert/ca-key), Server certificate (server-cert.pem) and key
(server-key.pem), and a client certificate (client-cert.pem) and key (client-key.pem).
*/
func (config KeyConfig) InitializeKeys() (err error) {
	autoFlag := os.Getenv(EnvAutoCreate)
	auto := true
	if autoFlag != "" && strings.ToLower(autoFlag[0:1]) == "f" {
		log.Warn("Auto self-sign create is disabled (HEXA_AUTO_SELFSIGN). Will not generate keys.")
		auto = false
	}

	var caPrivKey *rsa.PrivateKey

	// set up our CA certificate
	config.CaConfig = &x509.Certificate{
		SerialNumber:          big.NewInt(2019),
		Subject:               config.PkixName,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	if config.RootKeyExists() {

		log.Info(fmt.Sprintf("Loading existing CA Key from %s ...", config.CaKeyFile))
		keyBytes, err := os.ReadFile(config.CaKeyFile)
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
			config.CaPrivKey = caPrivKey
			if err != nil {
				return err
			}
		}

	} else if auto {

		log.Info("Generating new CA key pair...")
		// create our private and public key
		caPrivKey, err = rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return err
		}
		config.CaPrivKey = caPrivKey

		caPrivKeyPEM := new(bytes.Buffer)
		_ = pem.Encode(caPrivKeyPEM, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
		})
		log.Debug("Writing out CA Key to: " + config.CaKeyFile)
		err = os.WriteFile(config.CaKeyFile, caPrivKeyPEM.Bytes(), 0644)
		if err != nil {
			return err
		}

		caBytes, err := x509.CreateCertificate(rand.Reader, config.CaConfig, config.CaConfig, &caPrivKey.PublicKey, caPrivKey)
		if err != nil {
			return err
		}
		// pem encode
		caPEM := new(bytes.Buffer)
		_ = pem.Encode(caPEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caBytes,
		})

		log.Debug("Writing out CA Public Cert to: " + config.CaCertFile)

		err = os.WriteFile(config.CaCertFile, caPEM.Bytes(), 0644)
		if err != nil {
			return err
		}
	}

	// set up our server certificate

	var dnsNames []string
	domainName := os.Getenv(EnvServerDNS)
	if domainName == "" {
		dnsNames = []string{"hexa_bundle-server", "hexa-opaBundle-server"}
	} else {
		dnsNames = strings.Split(domainName, ",")
	}

	if !config.ServerCertExists() && auto {
		log.Info("Generating server key pair")
		certPEM, certPrivKeyPEM, err := config.generateCert(
			config.CaConfig,
			caPrivKey,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			dnsNames,
		)
		if err != nil {
			return err
		}
		log.Debug("Writing out Server Cert to: " + config.ServerCertPath)
		err = os.WriteFile(config.ServerCertPath, certPEM, 0644)
		if err != nil {
			return err
		}
		log.Debug("Writing out Server Key to: " + config.ServerKeyPath)
		err = os.WriteFile(config.ServerKeyPath, certPrivKeyPEM, 0644)
		if err != nil {
			return err
		}
	}
	return
}

func (config KeyConfig) GenerateClientKeys(keyPath, certPath string) (err error) {
	// set up our client certificate
	log.Info("Generating client keys")
	clientCertPEM, clientCertPrivKeyPEM, err := config.generateCert(
		config.CaConfig,
		config.CaPrivKey,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		[]string{},
	)
	if err != nil {
		return err
	}

	if certPath == "" {
		certPath = filepath.Join(config.CertDir, "client-cert.pem")
	}
	if keyPath == "" {
		keyPath = filepath.Join(config.CertDir, "client-key.pem")
	}
	log.Info("Writing out Client Cert to: " + certPath)
	err = os.WriteFile(certPath, clientCertPEM, 0644)
	if err != nil {
		return err
	}
	log.Info("Writing out Client Key to: " + keyPath)
	err = os.WriteFile(keyPath, clientCertPrivKeyPEM, 0644)
	if err != nil {
		return err
	}

	return nil
}

func (config KeyConfig) generateCert(
	ca *x509.Certificate,
	caPrivKey *rsa.PrivateKey,
	keyUsage []x509.ExtKeyUsage,
	dnsNames []string) ([]byte, []byte, error) {

	// generate a random serial number (a real cert authority would have some logic behind this)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      config.PkixName,
		DNSNames:     dnsNames,
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(2, 0, 0),
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

// CheckCaInstalled will check if a CA certificate has been installed in the http.Client or if nil, the system cert pool
func CheckCaInstalled(client *http.Client) {
	// Note; this is not tested because we don't want to install temporary test certs.
	caCertPath := os.Getenv(EnvCertCaPubKey)

	if caCertPath != "" {
		caCertPem, err := os.ReadFile(caCertPath)
		if err != nil {
			log.Warn("Error reading CA certificate: " + err.Error())
		}
		var caPool *x509.CertPool
		if client != nil {
			log.Debug("Installing CA certificate into HTTP client", "file", caCertPath)
			caPool = x509.NewCertPool()
			t := &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: caPool},
			}
			client.Transport = t
		} else {
			log.Debug("Installing CA certificate into system cert pool", "file", caCertPath)
			caPool, _ = x509.SystemCertPool()
		}
		ok := caPool.AppendCertsFromPEM(caCertPem)
		if !ok {
			log.Error("Error loading CA PEM")
		}

	}
}

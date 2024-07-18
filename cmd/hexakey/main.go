/*
hexakey is a command line tool that can be used to generate a set of self-signed keys for use by
the hexaBundleServer, hexaOpa server, and the Hexa AuthZen server.

USAGE:

	hexakey -type=tls
	hexakey -type=jwt -action=init -dir=./certs

This will generate a CA cert/key pair and use that to sign Server cert/key pair
and Client cert/key pair.

Use these certs for tests such as websupport_test and orchestrator_test.
*/
package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hexa-org/policy-mapper/pkg/keysupport"
	"github.com/hexa-org/policy-mapper/pkg/tokensupport"
	"github.com/hexa-org/policy-opa/pkg/hexaConstants"
)

func doTlsKeys() {
	config := keysupport.GetKeyConfig()

	// initialize if root key does not exist
	if !config.RootKeyExists() {
		// set up our CA certificate -- this is to work around a bug with InitializeCa
		if config.CaConfig == nil {
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
		}
		err := config.InitializeCa()
		if err != nil {
			panic(err)
		}
	}
}

var (
	typeFlag    *string
	cmdFlag     *string
	dirFlag     *string
	keyfileFlag *string
	scopeFlag   *string
	mailFlag    *string
	helpFlag    *bool
	keyPath     string
)

func init() {
	keyPath = os.Getenv(keysupport.EnvCertDirectory)
	if keyPath == "" {
		pathHome := os.Getenv("HOME")
		keyPath = filepath.Join(pathHome, "./.certs")
	}

	typeFlag = flag.String("type", "", "one of tls|jwt")
	cmdFlag = flag.String("action", "issue", "one of init|issue")
	dirFlag = flag.String("dir", keyPath, "filepath for storing keys")
	keyfileFlag = flag.String("keyfile", "", "Path to existing private key")
	scopeFlag = flag.String("scopes", "az", "az,bundle,root")
	mailFlag = flag.String("mail", "", "email address for user of token")
	helpFlag = flag.Bool("help", false, "To return help")
}

func start() {
	fmt.Println(fmt.Sprintf("Hexa Key Tool (Version: %s)", hexaConstants.HexaOpaVersion))

	flag.Parse()

	arg := flag.Arg(0)
	if (helpFlag != nil && *helpFlag) || strings.EqualFold("help", arg) {
		fmt.Println(`
hexakey generates certificates and tokens for use with the Hexa Bundle Server and AuthZen servers

To generate self-signed CA for use with TLS (ca-cert.pem):
hexakey -type=tls

To create a JWT certificate issuer use
hexakey -type=jwt --action=init --dir=./certs`)
		return
	}

	if dirFlag != nil {
		_ = os.Setenv(tokensupport.EnvTknKeyDirectory, *dirFlag)
		_ = os.Setenv(keysupport.EnvCertDirectory, *dirFlag)
	} else {
		_ = os.Setenv(keysupport.EnvCertDirectory, keyPath)
	}

	switch strings.ToLower(*typeFlag) {
	case "tls":
		existDir := os.Getenv(keysupport.EnvCertDirectory)
		certDir := existDir
		if dirFlag != nil && *dirFlag != "" {
			_ = os.Setenv(keysupport.EnvCertDirectory, *dirFlag)
			certDir = *dirFlag
		}
		fmt.Println(fmt.Sprintf("\nInitializing self-signed CA keys for TLS in: %s", certDir))
		doTlsKeys()
		if existDir != "" {
			_ = os.Setenv(keysupport.EnvCertDirectory, existDir)
		}
		return
	case "jwt":
		certDir := *dirFlag

		_, err := os.Stat(certDir)
		if os.IsNotExist(err) {
			_ = os.Mkdir(certDir, 0755)
		}
		_ = os.Setenv(tokensupport.EnvTknKeyDirectory, certDir)
		keyFileName := filepath.Join(certDir, tokensupport.DefTknPrivateKeyFile)

		switch strings.ToLower(*cmdFlag) {
		case "init":
			handler, err := tokensupport.GenerateIssuerKeys("authzen", false)
			if err != nil {
				fmt.Println(err.Error())
				return
			}
			fmt.Println(fmt.Sprintf("Token public and private keys generated in %s", handler.KeyDir))
		case "issue":
			useKey := keyFileName
			if keyfileFlag != nil && *keyfileFlag != "" {
				useKey = *keyfileFlag
			}
			_ = os.Setenv(tokensupport.EnvTknPrivateKeyFile, useKey)
			handler, err := tokensupport.LoadIssuer("authzen")
			if err != nil {
				fmt.Println(err.Error())
				return
			}

			scopes := strings.Split(strings.ToLower(*scopeFlag), ",")
			for _, scope := range scopes {
				switch scope {
				case tokensupport.ScopeAdmin, tokensupport.ScopeBundle, tokensupport.ScopeDecision:
					// ok
				default:
					fmt.Println(fmt.Printf("Invalid scope [%s] detected.", scope))
					return
				}
			}
			if mailFlag == nil || *mailFlag == "" {
				fmt.Println("An email address (-mail) is required for the user of the token")
				return
			}
			var tokenString string
			tokenString, _ = handler.IssueToken(scopes, *mailFlag)

			fmt.Println("Bearer token issued:")
			fmt.Println(tokenString)
		default:
			fmt.Println("Select -action=init or -action=issue")
		}
	default:
		fmt.Println("Missing -type=jwt or -type=tls, see -help")
	}
}

func main() {
	start()
}

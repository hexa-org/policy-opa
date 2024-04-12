/*
keyTool is a command line tool that can be used to generate a set of self-signed keys for use by
the testBundleServer and hexaOpa server.

USAGE:

	go run main.go

This will generate a CA cert/key pair and use that to sign Server cert/key pair
and Client cert/key pair.

Use these certs for tests such as websupport_test and orchestrator_test.
*/
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hexa-org/policy-opa/pkg/keysupport"
	"github.com/hexa-org/policy-opa/pkg/tokensupport"
)

func doServer() {
	config := keysupport.GetKeyConfig()
	// get our ca and server certificate
	err := config.CreateSelfSignedKeys()
	if err != nil {
		panic(err)
	}
}

func main() {

	pathHome := os.Getenv("HOME")
	keyPath := filepath.Join(pathHome, "./.certs")

	typeFlag := flag.String("type", "jwt", "one of tls|jwt")
	cmdFlag := flag.String("action", "token", "one of init|issue")
	dirFlag := flag.String("dir", keyPath, "filepath for storing keys")
	keyfileFlag := flag.String("keyfile", "", "Path to existing private key")
	scopeFlag := flag.String("scopes", "az", "az,bundle,root")
	mailFlag := flag.String("mail", "", "email address for user of token")
	flag.Parse()

	switch strings.ToLower(*typeFlag) {
	case "tls":
		doServer()
	case "jwt":
		_, err := os.Stat(*dirFlag)
		if os.IsNotExist(err) {
			_ = os.Mkdir(*dirFlag, 0755)
		}
		keyFileName := filepath.Join(*dirFlag, tokensupport.DefTknPrivFileName)

		switch strings.ToLower(*cmdFlag) {
		case "init":
			handler, err := tokensupport.GenerateIssuer("authzen", keyFileName)
			if err != nil {
				fmt.Println(err.Error())
				return
			}
			fmt.Println(fmt.Sprintf("Token public and private keys generated in %s", handler.KeyDir))
		case "issue":
			useKey := keyFileName
			if *keyfileFlag != "" {
				useKey = *keyfileFlag
			}
			handler, err := tokensupport.LoadIssuer("authzen", useKey)
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
			if *mailFlag == "" {
				fmt.Println("An email address (-mail) is required for the user of the token")
				return
			}
			var tokenString string
			tokenString, err = handler.IssueToken(scopes, *mailFlag)
			if err != nil {
				fmt.Println(err.Error())
				return
			}
			fmt.Println("Bearer token issued:")
			fmt.Println(tokenString)
		default:
			fmt.Println("Select -action=init or -action=issue")
		}
	default:
		fmt.Println("Select -type=jwt or -type=tls")
	}
}

/*
genKeys is a command line tool that can be used to generate a set of self-signed keys for use by
the testBundleServer and hexaOpa server.

USAGE:

	go run generate_cert.go

This will generate a CA cert/key pair and use that to sign Server cert/key pair
and Client cert/key pair.

Use these certs for tests such as websupport_test and orchestrator_test.
*/
package main

import (
	"github.com/hexa-org/policy-opa/pkg/keysupport"
)

func main() {

	config := keysupport.GetKeyConfig()
	// get our ca and server certificate
	err := config.CreateSelfSignedKeys()
	if err != nil {
		panic(err)
	}

}

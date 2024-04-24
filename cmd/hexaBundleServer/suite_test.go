package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"testing"

	"github.com/hexa-org/policy-opa/pkg/tokensupport"
)

var bundleToken string
var badToken string
var adminToken string

func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	tokenDir, _ := os.MkdirTemp("", "hexaBundle-*")
	defer os.RemoveAll(tokenDir)
	_ = os.Setenv(tokensupport.EnvTknIssuer, "bundle")
	_ = os.Setenv(tokensupport.EnvTknKeyDirectory, tokenDir)
	_ = os.Unsetenv(tokensupport.EnvTknPubKeyFile)
	_ = os.Unsetenv(tokensupport.EnvTknPrivateKeyFile)

	handler, err := tokensupport.GenerateIssuerKeys("bundle", false)
	if err != nil {
		fmt.Println(err.Error())
		panic(err)
	}

	bundleToken, err = handler.IssueToken([]string{tokensupport.ScopeBundle}, "bundle@hexa.org")
	badToken, err = handler.IssueToken([]string{"wrongScope"}, "bundle@hexa.org")
	adminToken, err = handler.IssueToken([]string{tokensupport.ScopeAdmin}, "bundle@hexa.org")

	// Don't use token enforcement by default.
	os.Setenv(tokensupport.EnvTknEnforceMode, tokensupport.ModeEnforceAnonymous)

	code := m.Run()

	os.Exit(code)
}

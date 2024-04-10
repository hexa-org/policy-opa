package authZenApp

import (
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/config"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/decisionHandler"
)

// var az *AuthZenApp

type AuthZenApp struct {
	Server    *http.Server
	Router    *HttpRouter
	BaseUrl   *url.URL
	HostName  string
	Decision  *decisionHandler.DecisionHandler
	bundleDir string
}

func (az *AuthZenApp) Name() string {
	return "HexaAuthZen"
}

func (az *AuthZenApp) HealthCheck() bool {

	return true
}

func StartServer(addr string, baseUrlString string) *AuthZenApp {

	az := AuthZenApp{}

	az.bundleDir = os.Getenv(config.EnvBundleDir)
	if az.bundleDir == "" {
		// If a relative path is used, then join with the current executable path...
		fmt.Println("Environment variable BUNDLE_DIR not defined, defaulting..")
		az.bundleDir = config.DefBundlePath
	}

	az.Decision = decisionHandler.NewDecisionHandler()

	router := NewRouter(&az)
	az.Router = router

	server := http.Server{
		Addr:    addr,
		Handler: router.router,
	}

	config.ServerLog.Printf("Server[%s] listening on %s", az.Name(), addr)

	az.Server = &server

	name := ""
	if server.TLSConfig != nil {
		name = server.TLSConfig.ServerName
	}

	var baseUrl *url.URL
	var err error
	if baseUrlString == "" {
		baseUrl, _ = url.Parse("http://" + server.Addr + "/")
	} else {
		baseUrl, err = url.Parse(baseUrlString)
		if err != nil {
			config.ServerLog.Println(fmt.Sprintf("FATAL: Invalid BaseUrl[%s]: %s", baseUrlString, err.Error()))
		}
	}
	az.BaseUrl = baseUrl

	if name != "" {
		config.ServerLog.Println("TLS hostname: [" + name + "]")
	} else {
		config.ServerLog.Println("TLS not configured.")
	}

	az.HostName = name

	return &az
}

func (az *AuthZenApp) Shutdown() {

	config.ServerLog.Printf("[%s] Shutdown Complete.", az.Name())
}
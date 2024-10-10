package config

import (
	"log"
	"os"

	"github.com/hexa-org/policy-opa/pkg/hexaConstants"
)

const (
	HexaAuthZenVersion            string = hexaConstants.HexaOpaVersion
	EnvAuthUserPipFile            string = "AUTHZEN_USERPIP_FILE"
	EnvAuthZenDecDetail           string = "AUTHZEN_RESPONSE_DETAIL"
	EnvBundleDir                  string = "AUTHZEN_BUNDLE_DIR"
	EndpointAuthzenSingleDecision string = "/access/v1/evaluation"
	EndpointAuthzenQuery          string = "/access/v1/evaluations"
	EndpointOpaBundles            string = "/bundles"
	EndpointGetOpaBundles         string = "/bundles/bundle.tar.gz"
	HeaderRequestId               string = "X-Request-ID"
	DefBundlePath                 string = "/home/authZen/bundles"
	DemoAuthZenPolicy             string = "/deployments/authZen/data.json"
)

var ServerLog = log.New(os.Stdout, "HEXA-AUTHZ: ", log.Ldate|log.Ltime)

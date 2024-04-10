package config

import (
	"log"
	"os"
)

const (
	EnvAuthUserPipFile            string = "AUTHZ_USERPIPFILE"
	EnvBundleDir                  string = "BUNDLE_DIR"
	EndpointAuthzenSingleDecision string = "/access/v1/evaluation"
	EndpointAuthzenQuery          string = "/access/v1/evaluations"
	EndpointOpaBundles            string = "/bundles"
	EndpointGetOpaBundles         string = "/bundles/bundle.tar.gz"
	HeaderRequestId               string = "X-Request-ID"
	DefBundlePath                 string = "../resources/bundles"
	DefRegoPath                   string = "bundle/hexaPolicyV2.rego"
	DefIdqlPath                   string = "bundle/data.json"
)

var ServerLog = log.New(os.Stdout, "HEXA-AUTHZ: ", log.Ldate|log.Ltime)

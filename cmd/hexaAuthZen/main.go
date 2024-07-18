/*
hexaAuthZen Interop test server
*/
package main

import (
	"fmt"
	"os"

	"github.com/hexa-org/policy-mapper/pkg/keysupport"
	"github.com/hexa-org/policy-mapper/pkg/websupport"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/authZenApp"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/config"
	log "golang.org/x/exp/slog"
)

var mLog = config.ServerLog

func main() {
	mLog.Printf("Hexa AuthZen Server starting...")
	mLog.Println("Note: This AuthZen demo server does not support TLS and should be deployed behind a TLS proxy terminator (e.g. Google App Engine).")
	mLog.Printf(fmt.Sprintf("Version: %s", config.HexaAuthZenVersion))

	port := "8080"
	if found := os.Getenv("PORT"); found != "" {
		port = found
	}
	mLog.Printf("Starting on port %s", port)

	// listener, _ := net.Dial("tcp", addr)

	az := authZenApp.StartServer(":"+port, "")

	if websupport.IsTlsEnabled() {
		keyConfig := keysupport.GetKeyConfig()
		err := keyConfig.InitializeKeys()
		if err != nil {
			log.Error("Error initializing keys: " + err.Error())
			panic(err)
		}

		websupport.WithTransportLayerSecurity(keyConfig.ServerCertPath, keyConfig.ServerKeyPath, az.Server)
	}
	err := az.Server.ListenAndServe()
	if err != nil {
		mLog.Fatal(err.Error())
	}
}

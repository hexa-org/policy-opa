/*
hexaAuthZen Interop test server
*/
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/authZenApp"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/config"
)

var mLog = log.New(os.Stdout, "MAIN:   ", log.Ldate|log.Ltime)

func main() {
	mLog.Printf("Hexa AuthZen Server starting...")
	mLog.Printf(fmt.Sprintf("Version: %s", config.HexaAuthZenVersion))
	port := "8080"
	if found := os.Getenv("PORT"); found != "" {
		port = found
	}
	mLog.Printf("Starting on port %s", port)

	// listener, _ := net.Dial("tcp", addr)

	az := authZenApp.StartServer(":"+port, "")
	err := az.Server.ListenAndServe()
	if err != nil {
		mLog.Fatal(err.Error())
	}
}

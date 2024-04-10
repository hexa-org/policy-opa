/*
hexaAuthZen Interop test server
*/
package main

import (
	"log"
	"os"

	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/authZenApp"
)

var mLog = log.New(os.Stdout, "MAIN:   ", log.Ldate|log.Ltime)

func main() {
	mLog.Printf("i2goSignals server starting...")
	mLog.Printf("Version: 0.0.1")
	port := "8888"
	if found := os.Getenv("PORT"); found != "" {
		port = found
	}

	baseUrl := "127.0.0.1:" + port + "/"
	if found := os.Getenv("BASE_URL"); found != "" {
		baseUrl = found
	}
	mLog.Println("Base URL: " + baseUrl)

	// listener, _ := net.Dial("tcp", addr)

	az := authZenApp.StartServer(":"+port, baseUrl)
	err := az.Server.ListenAndServe()
	if err != nil {
		mLog.Fatal(err.Error())
	}
}

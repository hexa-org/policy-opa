package authZenApp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hexa-org/policy-opa/api/infoModel"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/config"
	"github.com/hexa-org/policy-opa/pkg/compressionsupport"
)

const Header_Email string = "X-JWT-EMAIL"

func (az *AuthZenApp) Index(w http.ResponseWriter, r *http.Request) {
	test := r.UserAgent()
	_, _ = fmt.Fprintf(w, "Hexa Authzen Test Server\n\nHello %s", test)
}

/*
func (az *AuthZenApp) checkAuthorization(scopes []string, r *http.Request) int {
	if az.TokenAuthorizer != nil {
		token, stat := az.TokenAuthorizer.ValidateAuthorization(r, scopes)
		if token != nil {
			r.Header.Set(Header_Email, token.Email)
		}
		return stat
	}
	return http.StatusOK // For tests, just return ok when token validator not initialized
}
*/

func (az *AuthZenApp) HandleEvaluation(w http.ResponseWriter, r *http.Request) {
	requestId := r.Header.Get(config.HeaderRequestId)
	if requestId != "" {
		w.Header().Set(config.HeaderRequestId, requestId)
	}

	var jsonRequest infoModel.AuthRequest
	err := json.NewDecoder(r.Body).Decode(&jsonRequest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resp, err, status := az.Decision.ProcessDecision(jsonRequest)
	if err != nil {
		tid := requestId
		if tid == "" {
			tid = "UNK"
		}
		config.ServerLog.Println(fmt.Sprintf("Unexpected decision error (id: %s): %s", tid, err.Error()))
		http.Error(w, fmt.Sprintf("Unexpected internal decision error (id: %s", tid), status)
		return
	}

	w.WriteHeader(status)
	if resp != nil {
		bodyBytes, _ := json.Marshal(resp)
		_, _ = w.Write(bodyBytes)
	}

}

func (az *AuthZenApp) HandleQueryEvaluation(w http.ResponseWriter, r *http.Request) {
	requestId := r.Header.Get(config.HeaderRequestId)

	var jsonRequest infoModel.QueryRequest
	err := json.NewDecoder(r.Body).Decode(&jsonRequest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resp, err, status := az.Decision.ProcessQueryDecision(jsonRequest, r)
	if err != nil {
		tid := requestId
		if tid == "" {
			tid = "UNK"
		}
		config.ServerLog.Println(fmt.Sprintf("Unexpected decision error (id: %s): %s", tid, err.Error()))
		http.Error(w, fmt.Sprintf("Unexpected internal decision error (id: %s", tid), status)
		return
	}

	if requestId != "" {
		w.Header().Set(config.HeaderRequestId, requestId)
	}

	if resp != nil {
		bodyBytes, _ := json.Marshal(resp)
		_, _ = w.Write(bodyBytes)
	}

	w.WriteHeader(status)
}

func handleError(msg string, err error, w http.ResponseWriter, status int) {
	if err != nil {
		config.ServerLog.Println(fmt.Sprintf("%s: %s", msg, err.Error()))
		http.Error(w, fmt.Sprintf("%s.\n%s", msg, err.Error()), status)
	}
}

func (az *AuthZenApp) saveExistingBundle() (string, error) {
	saveDir := fmt.Sprintf(".bundle-%d", rand.Uint64())
	savePath := filepath.Join(az.bundleDir, saveDir)

	dirEntry, err := os.ReadDir(az.bundleDir)
	if err != nil {
		return "", err
	}
	err = os.Mkdir(savePath, 0777)
	if err != nil {
		return "", err
	}
	for _, entry := range dirEntry {
		name := entry.Name()
		if name == saveDir || strings.HasPrefix(name, ".bundle") {
			continue
		}
		config.ServerLog.Println("saving: " + name)
		dest := filepath.Join(savePath, name)
		source := filepath.Join(az.bundleDir, name)
		err := os.Rename(source, dest)
		if err != nil {
			config.ServerLog.Println("Error moving file: " + err.Error())
		}
	}

	return savePath, nil
}

/*
BundleUpload accepts an OPA tar bundle and replaces the current bundle package at az.BundleDir. Note the the process
followed is:

1. Save the existing bundle directory to ".bundle-<number>"
2. Unzip and untar bundle to az.bundleDir (this bundle should contain an bundle folder)
3. Attempt to reload Rego.
4. If rego fails, restore the old bundle and server
*/
func (az *AuthZenApp) BundleUpload(writer http.ResponseWriter, r *http.Request) {
	_ = r.ParseMultipartForm(32 << 20)
	bundleFile, _, err := r.FormFile("bundle")
	if err != nil {
		config.ServerLog.Println(fmt.Sprintf("Error retrieving bundle file: %s", err.Error()))
	}
	gzip, _ := compressionsupport.UnGzip(bundleFile)
	rand.New(rand.NewSource(time.Now().UnixNano()))

	config.ServerLog.Println("Saving current bundle")
	restorePath, err := az.saveExistingBundle()
	if err != nil {
		handleError("Error updating bundle", err, writer, http.StatusInternalServerError)
		return
	}

	_ = compressionsupport.UnTarToPath(bytes.NewReader(gzip), az.bundleDir)

	// TODO: Should do some work to validate the bundle.
	err = az.Decision.ProcessUploadOpa()
	if err != nil {
		handleError("Error updating bundle", err, writer, http.StatusBadRequest)
		bundleDir := filepath.Join(az.bundleDir, "bundle")
		_ = os.RemoveAll(bundleDir)
		_ = os.Rename(filepath.Join(restorePath, "bundle"), bundleDir)
		return
	}

	writer.WriteHeader(http.StatusCreated)
}

func (az *AuthZenApp) getTarBundle() ([]byte, error) {
	return compressionsupport.TarFromPath(az.bundleDir)
}

func (az *AuthZenApp) BundleDownload(writer http.ResponseWriter, _ *http.Request) {
	tar, _ := az.getTarBundle()
	writer.Header().Set("Content-Type", "application/gzip")
	_ = compressionsupport.Gzip(writer, tar)
	writer.Header()
}

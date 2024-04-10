package authZenApp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/config"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/infoModel"
	"github.com/hexa-org/policy-opa/pkg/compressionsupport"
)

func (az *AuthZenApp) Index(w http.ResponseWriter, r *http.Request) {
	test := r.UserAgent()
	_, _ = fmt.Fprintf(w, "Hello %s", test)
}

func (az *AuthZenApp) HandleEvaluation(w http.ResponseWriter, r *http.Request) {
	requestId := r.Header.Get(config.HeaderRequestId)
	var jsonRequest infoModel.AuthRequest
	err := json.NewDecoder(r.Body).Decode(&jsonRequest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resp, err, status := az.Decision.ProcessDecision(jsonRequest, r)
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

	bodyBytes, _ := json.Marshal(resp)
	_, _ = w.Write(bodyBytes)
	w.WriteHeader(http.StatusOK)
}

func (az *AuthZenApp) HandleQueryEvaluation(w http.ResponseWriter, r *http.Request) {
	requestId := r.Header.Get(config.HeaderRequestId)

	if requestId != "" {
		w.Header().Set(config.HeaderRequestId, requestId)
	}

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
		if name == saveDir {
			continue
		}
		fmt.Println("moving: " + name)
		dest := filepath.Join(savePath, name)
		source := filepath.Join(az.bundleDir, name)
		err := os.Rename(source, dest)
		if err != nil {
			fmt.Println("Error moving file: " + err.Error())
		}
	}

	return savePath, nil
}

func (az *AuthZenApp) BundleUpload(writer http.ResponseWriter, r *http.Request) {
	_ = r.ParseMultipartForm(32 << 20)
	bundleFile, _, err := r.FormFile("bundle")
	if err != nil {
		fmt.Println(err.Error())
	}
	gzip, _ := compressionsupport.UnGzip(bundleFile)
	rand.New(rand.NewSource(time.Now().UnixNano()))

	config.ServerLog.Println("Saving existing bundle")
	restorePath, err := az.saveExistingBundle()
	if err != nil {
		handleError("Error updating bundle", err, writer, http.StatusInternalServerError)
		return
	}

	_ = compressionsupport.UnTarToPath(bytes.NewReader(gzip), filepath.Join(az.bundleDir, "bundle"))

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
	return compressionsupport.TarFromPath(fmt.Sprintf("%s/%s", az.bundleDir, "bundle"))
}

func (az *AuthZenApp) BundleDownload(writer http.ResponseWriter, _ *http.Request) {

	tar, _ := az.getTarBundle()
	writer.Header().Set("Content-Type", "application/gzip")
	_ = compressionsupport.Gzip(writer, tar)
	writer.Header()
}

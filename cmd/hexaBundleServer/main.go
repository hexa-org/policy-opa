package main

import (
	"bytes"
	"crypto/tls"
	"fmt"

	"io/fs"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/config"
	"github.com/hexa-org/policy-opa/pkg/compressionsupport"
	"github.com/hexa-org/policy-opa/pkg/keysupport"
	"github.com/hexa-org/policy-opa/pkg/tokensupport"
	"github.com/hexa-org/policy-opa/pkg/websupport"
)

const EnvBundleDir = "BUNDLE_DIR"
const DEF_TEST_BUNDLE_PATH string = "../resources/bundles"
const Header_Email string = "X-JWT-EMAIL"

func App(addr string, bundleDir string) *http.Server {
	basic := NewBundleApp(bundleDir)
	return websupport.Create(addr, basic.loadHandlers(), websupport.Options{})
}

type BundleApp struct {
	bundleDir      string
	TokenValidator *tokensupport.TokenHandler
}

func NewBundleApp(bundleDir string) BundleApp {
	app := BundleApp{bundleDir: bundleDir}
	authMode := os.Getenv(tokensupport.EnvTknEnforceMode)
	if !strings.EqualFold(tokensupport.ModeEnforceAnonymous, authMode) {
		issuerName := os.Getenv(tokensupport.EnvTknIssuer)
		if issuerName == "" {
			issuerName = "authzen"
		}
		var err error
		app.TokenValidator, err = tokensupport.TokenValidator(issuerName)
		if err != nil {
			config.ServerLog.Println(fmt.Sprintf("FATAL Loading Token Validator: %s", err.Error()))
			panic(err)
		}
	}

	return app
}

func (a *BundleApp) checkAuthorization(scopes []string, r *http.Request) int {
	if a.TokenValidator != nil {
		token, stat := a.TokenValidator.ValidateAuthorization(r, scopes)
		if token != nil {
			r.Header.Set(Header_Email, token.Email)
		}
		return stat
	}
	return http.StatusOK // For tests, just return ok when token validator not initialized
}

func (a *BundleApp) download(writer http.ResponseWriter, r *http.Request) {
	authStatus := a.checkAuthorization([]string{tokensupport.ScopeBundle}, r)
	if authStatus != http.StatusOK {
		writer.WriteHeader(authStatus)
		return
	}

	tar, _ := compressionsupport.TarFromPath(fmt.Sprintf("%s/%s", a.bundleDir, a.latest(a.bundleDir)))
	writer.Header().Set("Content-Type", "application/gzip")
	_ = compressionsupport.Gzip(writer, tar)
	writer.Header()
}

func (a *BundleApp) latest(dir string) string {
	available := a.available(dir)
	if len(available) == 0 {
		return ""
	}
	return available[0].Name()
}

func (a *BundleApp) available(dir string) []fs.FileInfo {
	available := make([]fs.FileInfo, 0)
	dirInfo, err := os.Stat(dir)
	if os.IsExist(err) && dirInfo.IsDir() {
		_ = fs.WalkDir(os.DirFS(dir), ".", func(path string, d fs.DirEntry, err error) error {
			if d != nil {
				info, _ := d.Info()
				if info.Name() == "." {
					return nil
				}
				available = append(available, info)
				return fs.SkipDir
			}
			return fs.SkipDir
		})
	}
	sort.Slice(available, func(i, j int) bool {
		return available[i].ModTime().Unix() > available[j].ModTime().Unix()
	})
	return available
}

func (a *BundleApp) upload(writer http.ResponseWriter, r *http.Request) {
	authStatus := a.checkAuthorization([]string{tokensupport.ScopeBundle}, r)
	if authStatus != http.StatusOK {
		writer.WriteHeader(authStatus)
		return
	}
	_ = r.ParseMultipartForm(32 << 20)
	bundleFile, _, _ := r.FormFile("bundle")
	gzip, _ := compressionsupport.UnGzip(bundleFile)
	rand.New(rand.NewSource(time.Now().UnixNano()))

	path := filepath.Join(a.bundleDir, fmt.Sprintf(".bundle-%d", rand.Uint64()))
	_ = compressionsupport.UnTarToPath(bytes.NewReader(gzip), path)
	writer.WriteHeader(http.StatusCreated)
}

func (a *BundleApp) reset(writer http.ResponseWriter, r *http.Request) {
	authStatus := a.checkAuthorization([]string{tokensupport.ScopeAdmin}, r)
	if authStatus != http.StatusOK {
		writer.WriteHeader(authStatus)
		return
	}
	for _, available := range a.available(a.bundleDir) {
		if strings.Index(available.Name(), ".bundle") == 0 {
			path := filepath.Join(a.bundleDir, available.Name())
			err := os.RemoveAll(path)
			if err != nil {
				log.Printf("Unable to remove bundle %v", path)
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
	}
}

func (a *BundleApp) loadHandlers() func(router *mux.Router) {
	return func(router *mux.Router) {
		router.HandleFunc("/bundles/bundle.tar.gz", a.download).Methods("GET")
		router.HandleFunc("/bundles", a.upload).Methods("POST")
		router.HandleFunc("/reset", a.reset).Methods("GET")
	}
}

func newApp(addr string, bundlePath string) (*http.Server, net.Listener) {
	if found := os.Getenv("PORT"); found != "" {
		host, _, _ := net.SplitHostPort(addr)
		addr = fmt.Sprintf("%v:%v", host, found)
	}
	log.Printf("Found server address %v", addr)

	if found := os.Getenv("HOST"); found != "" {
		_, port, _ := net.SplitHostPort(addr)
		addr = fmt.Sprintf("%v:%v", found, port)
	}
	log.Printf("Found server host %v", addr)

	listener, _ := net.Listen("tcp", addr)

	bundleDir := os.Getenv(EnvBundleDir)
	if bundleDir == "" {
		// If a relative path is used, then join with the current executable path...
		fmt.Println("Environment variable BUNDLE_DIR not defined.")
		if strings.Index(bundlePath, DEF_TEST_BUNDLE_PATH) == 0 {
			fmt.Println("Configuring for testing mode...")
			// This is mainly used for testing
			_, file, _, _ := runtime.Caller(0)
			bundleDir = filepath.Join(file, bundlePath)
		} else {
			bundleDir = bundlePath
		}
	}

	app := App(listener.Addr().String(), bundleDir)

	keyConfig := keysupport.GetKeyConfig()

	if keyConfig.ServerKeyExists() {
		log.Println(fmt.Sprintf("Loading existing server EnvBundleDir from: %s", keyConfig.ServerKeyPath))
		key, err := os.ReadFile(keyConfig.ServerKeyPath)
		if err != nil {
			panic(fmt.Sprintf("invalid SERVER_KEY path: %s", err))
		}
		cert, err := os.ReadFile(keyConfig.ServerCertPath)
		if err != nil {
			panic(fmt.Sprintf("invalid SERVER_CERT path: %s", err))
		}
		pair, err := tls.X509KeyPair(cert, key)
		if err != nil {
			panic(fmt.Sprintf("invalid cert/key pair: %s", err))
		}
		app.TLSConfig = &tls.Config{
			// todo - tls client auth? Should we require client cert verification?
			Certificates: []tls.Certificate{pair},
		}
	} else {
		if !keyConfig.CertDirExists() {
			panic(fmt.Sprintf("Unable to locate certificate directory: %s", keyConfig.CertDir))
		}
		phrase := " Generating new root EnvBundleDir and server keys."
		if keyConfig.RootKeyExists() {
			phrase = " Using existing root EnvBundleDir to generate new server keys."
		}
		log.Println("Server certificate not found." + phrase)
		err := keyConfig.CreateSelfSignedKeys()
		if err != nil {
			panic(fmt.Sprintf("Automatic EnvBundleDir generation failed: %s", err))
		}
	}

	websupport.WithTransportLayerSecurity(keyConfig.ServerCertPath, keyConfig.ServerKeyPath, app)

	return app, listener
}

func main() {

	app, listener := newApp("0.0.0.0:8889", "")
	websupport.Start(app, listener)
}

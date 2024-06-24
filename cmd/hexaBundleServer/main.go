package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io/fs"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hexa-org/policy-mapper/pkg/keysupport"
	"github.com/hexa-org/policy-mapper/pkg/oauth2support"
	log "golang.org/x/exp/slog"

	"github.com/gorilla/mux"
	"github.com/hexa-org/policy-mapper/providers/openpolicyagent"

	"github.com/hexa-org/policy-mapper/pkg/tokensupport"
	"github.com/hexa-org/policy-mapper/pkg/websupport"
	"github.com/hexa-org/policy-opa/pkg/compressionsupport"
)

//go:embed resources/hexaIndustries-data.json
var hexaPolicyBytes []byte // hexaPolicyBytes holds the default policy which is used by the HexaIndustries demo

const EnvBundleDir = "BUNDLE_DIR"
const DefBundlePath string = "/home/resources/bundles"

func App(addr string, bundleDir string) *http.Server {
	basic := NewBundleApp(bundleDir)

	server := websupport.Create(addr, basic.loadHandlers(basic.tokenAuthorizer), websupport.Options{})
	keyConfig := keysupport.GetKeyConfig()
	err := keyConfig.InitializeKeys() // if new server, will generate keys automatically
	if err != nil {
		log.Error("Error initializing keys: " + err.Error())
		panic(err)
	}

	websupport.WithTransportLayerSecurity(keyConfig.ServerCertPath, keyConfig.ServerKeyPath, server)
	return server
}

type BundleApp struct {
	bundleDir       string
	tokenAuthorizer *oauth2support.ResourceJwtAuthorizer
}

func NewBundleApp(bundleDir string) BundleApp {
	app := BundleApp{bundleDir: bundleDir}
	var err error
	app.tokenAuthorizer, err = oauth2support.NewResourceJwtAuthorizer()
	if err != nil {
		log.Error(fmt.Sprintf("FATAL Loading Token Validator: %s", err.Error()))
		panic(err)
	}

	_, err = os.Stat(filepath.Join(bundleDir, "bundle"))
	if os.IsNotExist(err) {
		log.Warn("Bundle directory not found, initializing with default HexaIndustries policy bundle")

		bundle, err := openpolicyagent.MakeHexaBundle(hexaPolicyBytes)
		if err != nil {
			log.Error("Error creating default bundle: %s", err)
			return app
		}

		gzip, _ := compressionsupport.UnGzip(bytes.NewReader(bundle.Bytes()))

		_ = compressionsupport.UnTarToPath(bytes.NewReader(gzip), bundleDir)
	}

	return app
}

func (a *BundleApp) download(writer http.ResponseWriter, r *http.Request) {
	latestBundle := a.latest(a.bundleDir)

	tar, _ := compressionsupport.TarFromPath(fmt.Sprintf("%s/%s", a.bundleDir, latestBundle))
	writer.Header().Set("Content-Type", "application/gzip")
	_ = compressionsupport.Gzip(writer, tar)
	writer.Header()
	subject := r.Header.Get(oauth2support.Header_Subj)
	log.Info("Download bundle", "subject", subject, "address", r.RemoteAddr)
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
	_ = r.ParseMultipartForm(32 << 20)
	bundleFile, _, _ := r.FormFile("bundle")
	gzip, _ := compressionsupport.UnGzip(bundleFile)
	rand.New(rand.NewSource(time.Now().UnixNano()))

	path := filepath.Join(a.bundleDir, fmt.Sprintf(".bundle-%d", rand.Uint64()))
	_ = compressionsupport.UnTarToPath(bytes.NewReader(gzip), path)
	writer.WriteHeader(http.StatusCreated)
	subject := r.Header.Get(oauth2support.Header_Subj)
	log.Info("Upload bundle", "subject", subject, "address", r.RemoteAddr)
}

func (a *BundleApp) reset(writer http.ResponseWriter, r *http.Request) {
	subject := r.Header.Get(oauth2support.Header_Subj)
	log.Warn("Bundle RESET received", "subject", subject, "address", r.RemoteAddr)
	for _, available := range a.available(a.bundleDir) {
		if strings.Index(available.Name(), ".bundle") == 0 {
			path := filepath.Join(a.bundleDir, available.Name())
			err := os.RemoveAll(path)
			if err != nil {
				log.Error("Unable to remove bundle %v", path)
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
	}
}

func (a *BundleApp) loadHandlers(jwtAuthorizer *oauth2support.ResourceJwtAuthorizer) func(router *mux.Router) {

	return func(router *mux.Router) {
		router.HandleFunc("/bundles/bundle.tar.gz", oauth2support.JwtAuthenticationHandler(a.download, jwtAuthorizer, []string{tokensupport.ScopeBundle, tokensupport.ScopeAdmin})).Methods("GET")
		router.HandleFunc("/bundles", oauth2support.JwtAuthenticationHandler(a.upload, jwtAuthorizer, []string{tokensupport.ScopeBundle, tokensupport.ScopeAdmin})).Methods("POST")
		router.HandleFunc("/reset", oauth2support.JwtAuthenticationHandler(a.reset, jwtAuthorizer, []string{tokensupport.ScopeAdmin})).Methods("GET")
	}
}

func newApp(addr string) (*http.Server, net.Listener) {
	if found := os.Getenv("PORT"); found != "" {
		host, _, _ := net.SplitHostPort(addr)
		addr = fmt.Sprintf("%v:%v", host, found)
	}
	log.Debug("Found server address %v", addr)

	if found := os.Getenv("HOST"); found != "" {
		_, port, _ := net.SplitHostPort(addr)
		addr = fmt.Sprintf("%v:%v", found, port)
	}
	log.Debug("Found server host %v", addr)

	listener, _ := net.Listen("tcp", addr)

	bundleDir := os.Getenv(EnvBundleDir)
	if bundleDir == "" {
		log.Warn("Environment variable BUNDLE_DIR not defined, using: %s", DefBundlePath)
		bundleDir = DefBundlePath
	}

	app := App(listener.Addr().String(), bundleDir)

	return app, listener
}

func main() {
	log.Info("Hexa OPA Bundle Server starting...", "version", "0.65.2")
	app, listener := newApp("0.0.0.0:8889")
	websupport.Start(app, listener)
}

package main

import (
	"embed"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/hexa-org/policy-mapper/pkg/keysupport"
	"github.com/hexa-org/policy-mapper/pkg/oidcSupport"
	"github.com/hexa-org/policy-mapper/pkg/sessionSupport"
	log "golang.org/x/exp/slog"

	"github.com/gorilla/mux"
	"github.com/hexa-org/policy-mapper/pkg/websupport"
	"github.com/hexa-org/policy-opa/pkg/decisionsupport"

	"github.com/hexa-org/policy-opa/pkg/decisionsupportproviders"
)

//go:embed resources/static
var staticResources embed.FS

//go:embed resources
var resources embed.FS

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

func App(addr string) *http.Server {
	session := sessionSupport.NewSessionManager()

	basic := NewBasicApp(session)
	server := websupport.Create(addr, basic.loadHandlers(), websupport.Options{})

	return server
}

type BasicApp struct {
	session sessionSupport.SessionManager
}

func NewBasicApp(session sessionSupport.SessionManager) BasicApp {
	return BasicApp{session}
}

func (a *BasicApp) dashboard(writer http.ResponseWriter, req *http.Request) {
	log.Info("dashboard requested", "addr", req.RemoteAddr)
	_ = websupport.ModelAndView(writer, &resources, "dashboard", a.principalAndLogout(req))
}

func (a *BasicApp) accounting(writer http.ResponseWriter, req *http.Request) {
	log.Info("accounting requested", "addr", req.RemoteAddr)
	_ = websupport.ModelAndView(writer, &resources, "accounting", a.principalAndLogout(req))
}

func (a *BasicApp) sales(writer http.ResponseWriter, req *http.Request) {
	log.Info("sales requested", "addr", req.RemoteAddr)
	_ = websupport.ModelAndView(writer, &resources, "sales", a.principalAndLogout(req))
}

func (a *BasicApp) humanresources(writer http.ResponseWriter, req *http.Request) {
	log.Info("humanresources requested", "addr", req.RemoteAddr)
	_ = websupport.ModelAndView(writer, &resources, "humanresources", a.principalAndLogout(req))
}

func (a *BasicApp) unauthorized(writer http.ResponseWriter, req *http.Request) {
	log.Info("unauthorized requested", "addr", req.RemoteAddr)
	_ = websupport.ModelAndView(writer, &resources, "unauthorized", a.principalAndLogout(req))
}

func (a *BasicApp) loadHandlers() func(router *mux.Router) {

	client := http.Client{}
	keysupport.CheckCaInstalled(&client)
	oidcHandler, err := oidcSupport.NewOidcClientHandler(a.session, &resources)
	oidcHandler.MainPage = "/dashboard"
	opaUrl := "https://0.0.0.0:8887/v1/data/hexaPolicy"
	if found := os.Getenv("OPA_SERVER_URL"); found != "" {
		opaUrl = found
	}
	log.Info(fmt.Sprintf("Using OPA PDP address %v", opaUrl))

	actionMap := map[string]string{}
	actionMap["/dashboard"] = "root"
	actionMap["/sales"] = "sales"
	actionMap["/accounting"] = "accounting"
	actionMap["/marketing"] = "marketing"
	actionMap["/humanresources"] = "humanresources"
	provider := decisionsupportproviders.OpaDecisionProvider{Client: &client, Url: opaUrl, Principal: "sales@hexaindustries.io", OidcHandler: oidcHandler}
	opaSupport := decisionsupport.DecisionSupport{
		Provider:     provider,
		Unauthorized: a.unauthorized,
		Skip:         []string{"/authorize", "/login", "/logout", "/redirect", "/health", "/metrics", "/styles", "/images", "/bundle", "/favicon.ico"},
		ActionMap:    actionMap,
		ResourceId:   "hexaIndustries",
	}

	return func(router *mux.Router) {
		oidcHandler.InitHandlers(router)
		if err != nil {
			log.Error(err.Error())
			log.Warn("OIDC Login is disabled")
		}
		router.Use(opaSupport.Middleware)
		if !oidcHandler.Enabled {
			// Normally oidcHandler puts up a login page. However when disabled, just to to dashboard
			router.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
				http.Redirect(writer, request, "/dashboard", http.StatusTemporaryRedirect)
			})
		}
		router.HandleFunc("/dashboard", oidcHandler.HandleSessionScope(a.dashboard, []string{"root"})).Methods("GET")
		router.HandleFunc("/sales", oidcHandler.HandleSessionScope(a.sales, []string{"sales"})).Methods("GET")
		router.HandleFunc("/accounting", oidcHandler.HandleSessionScope(a.accounting, []string{"accounting"})).Methods("GET")
		router.HandleFunc("/humanresources", oidcHandler.HandleSessionScope(a.humanresources, []string{"accounting"})).Methods("GET")

		fileServer := http.FileServer(http.FS(staticResources))
		router.PathPrefix("/").Handler(addPrefix("resources/static", fileServer))
	}
}

func addPrefix(prefix string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		req.URL.Path = prefix + req.URL.Path
		h.ServeHTTP(rw, req)
	})
}

func (a *BasicApp) principalAndLogout(req *http.Request) websupport.Model {
	session, err := a.session.Session(req)
	if err != nil {
		return websupport.Model{Map: map[string]interface{}{}}
	}
	principal := session.Email

	return websupport.Model{Map: map[string]interface{}{
		"provider_email": principal,
	}}
}

func newApp(addr string) (*http.Server, net.Listener) {

	if found := os.Getenv("PORT"); found != "" {
		host, _, _ := net.SplitHostPort(addr)
		addr = fmt.Sprintf("%v:%v", host, found)
	}
	log.Debug(fmt.Sprintf("Found server port %v", addr))

	if found := os.Getenv("HOST"); found != "" {
		_, port, _ := net.SplitHostPort(addr)
		addr = fmt.Sprintf("%v:%v", found, port)
	}
	log.Debug(fmt.Sprintf("Found server host %v", addr))

	listener, _ := net.Listen("tcp", addr)

	server := App(listener.Addr().String())

	if websupport.IsTlsEnabled() {
		keyConfig := keysupport.GetKeyConfig()
		err := keyConfig.InitializeKeys()
		if err != nil {
			log.Error("Error initializing keys: " + err.Error())
			panic(err)
		}

		websupport.WithTransportLayerSecurity(keyConfig.ServerCertPath, keyConfig.ServerKeyPath, server)
	}
	return server, listener
}

func main() {
	log.Info("Hexa Industries Demo Server starting...", "version", "0.65.2")
	websupport.Start(newApp("0.0.0.0:8886"))
}

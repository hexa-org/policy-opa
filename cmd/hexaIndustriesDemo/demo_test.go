//go:build disable

package main_test

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDemoFlow(t *testing.T) {
	demo := makeCmd("/cmd/hexaIndustriesDemo/demo.go", []string{"HOST=localhost", "PORT=8886", "OPA_SERVER_URL: http://localhost:8887/v1/data/authz/allow"})
	demoConfig := makeCmd("/cmd/hexaBundleServer/main.go", []string{"HOST=localhost", "PORT=8889"})
	anotherDemoConfig := makeCmd("/cmd/hexaBundleServer/main.go", []string{"HOST=localhost", "PORT=8890"})

	_, file, _, _ := runtime.Caller(0)
	testBundles := filepath.Join(file, "../../../cmd/hexaBundleServer/resources/bundles/.bundle-*")
	files, _ := filepath.Glob(testBundles)
	for _, f := range files {
		if err := os.RemoveAll(f); err != nil {
			panic(err)
		}
	}
	config := filepath.Join(file, "../../../cmd/hexaIndustriesDemo/test/resources/config.yaml")
	openPolicyAgent := exec.Command("opa", "run", "--server", "--addr", "localhost:8887", "-c", config)
	openPolicyAgent.Env = os.Environ()
	openPolicyAgent.Env = append(openPolicyAgent.Env, "HEXA_DEMO_CONFIG_URL=http://localhost:8889")
	openPolicyAgent.Stdout = os.Stdout
	openPolicyAgent.Stderr = os.Stderr
	openPolicyAgent.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	startCmd(demo, 8886)
	startCmd(demoConfig, 8889)
	startCmd(anotherDemoConfig, 8890)
	startCmd(openPolicyAgent, 8887)
	// startCmd(orchestrator, 8885)

	defer func() {
		stopCmds(openPolicyAgent, demoConfig, anotherDemoConfig, demo)
	}()

	assertContains(t, "http://localhost:8886/", "Great news, you're able to access this page.")

	assertContains(t, "http://localhost:8886/sales", "Great news, you're able to access this page.")

	assertContains(t, "http://localhost:8886/accounting", "Sorry, you're not able to access this page.")

	assertContains(t, "http://localhost:8886/humanresources", "Sorry, you're not able to access this page.")

	// test update

	// _, _ = db.Exec(deleteAll)
	// createAnIntegration([]byte(`{ "bundle_url": "http://localhost:8889/bundles/bundle.tar.gz" }`))
	// status, updateErr := updateIntegrationPolicy()
	// assert.Equal(t, http.StatusCreated, status.StatusCode)
	// assert.NoError(t, updateErr)

	time.Sleep(time.Duration(3) * time.Second) // waiting for opa to refresh the bundle

	assertContains(t, "http://localhost:8886/accounting", "Great news, you're able to access this page.")

	demoConfigResourceId := base64.StdEncoding.EncodeToString([]byte("http://localhost:8889/bundles/bundle.tar.gz"))
	assertContains(t, "http://localhost:8887/v1/data", demoConfigResourceId)

	// test erroneous

	// _, _ = db.Exec(deleteAll)
	createAnErroneousIntegration()

	resp, secondUpdateErr := updateIntegrationPolicy()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	assert.NoError(t, secondUpdateErr)

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "unable to update policy.\n", string(body))

	// test orchestration

	// _, _ = db.Exec(deleteAll)
	fromBundleUrl := "http://localhost:8889/bundles/bundle.tar.gz"
	fromKey := []byte(fmt.Sprintf(`{ "bundle_url": "%s"}`, fromBundleUrl))
	createAnIntegration(fromKey)

	toBundleUrl := "http://localhost:8890/bundles/bundle.tar.gz"
	toKey := []byte(fmt.Sprintf(`{ "bundle_url": "%s"}`, toBundleUrl))
	createAnIntegration(toKey)

	fromAppId, toAppId := appIdsToOrchestrate(fromBundleUrl, toBundleUrl)
	orchestratePolicy(fromAppId, toAppId)

	time.Sleep(time.Duration(3) * time.Second) // waiting for opa to refresh the bundle

	anotherDemoConfigResourceId := base64.StdEncoding.EncodeToString([]byte("http://localhost:8890/bundles/bundle.tar.gz"))
	assertContains(t, "http://localhost:8887/v1/data", anotherDemoConfigResourceId) // ensures that the resource id is not overwritten

	_, _ = http.Get("http://localhost:8889/reset")
}

func appIdsToOrchestrate(fromBundleUrl, toBundleUrl string) (fromAppId, toAppId string) {

	fromResourceId := base64.StdEncoding.EncodeToString([]byte(fromBundleUrl))
	toResourceId := base64.StdEncoding.EncodeToString([]byte(toBundleUrl))

	apps := listApplications()

	for _, oneApp := range apps.Applications {
		switch oneApp.ObjectId {
		case fromResourceId:
			fromAppId = oneApp.ID
		case toResourceId:
			toAppId = oneApp.ID
		default:
			log.Println("TestDemoFlow Ignore app")
		}
	}
	return
}
func assertContains(t *testing.T, url string, contains string) {
	resp, _ := http.Get(url)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), contains, url)
}

// / supporting structs

type Integration struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Provider string `json:"provider"`
	Key      []byte `json:"key"`
}

type Applications struct {
	Applications []Application `json:"applications"`
}

type Application struct {
	ID       string `json:"id"`
	ObjectId string `json:"object_id"`
}

type Orchestration struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// / supporting functions

func makeCmd(cmdString string, envs []string) *exec.Cmd {
	_, file, _, _ := runtime.Caller(0)
	path := filepath.Join(file, "../../../")
	commandPath := filepath.Join(path, cmdString)

	var args []string
	args = append([]string{commandPath}, args...)
	args = append([]string{"run"}, args...)

	cmd := exec.Command("go", args...)
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, envs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// assigning parent and child processes to a process group to ensure all process receive stop signal
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	return cmd
}

func startCmd(cmd *exec.Cmd, port int) {
	log.Printf("Starting cmd %v\n", cmd)
	go func() {
		err := cmd.Run()
		if err != nil {
			log.Printf("Unable to start cmd %v\n.", err)
		}
	}()
	waitForHealthy(fmt.Sprintf("localhost:%v", port))
}

func waitForHealthy(address string) {
	var isLive bool
	for !isLive {
		resp, err := http.Get(fmt.Sprintf("http://%s/health", address))
		if err == nil && resp.StatusCode == http.StatusOK {
			log.Println("Server is healthy.", address)
			isLive = true
		}
	}
}

func stopCmds(cmds ...*exec.Cmd) {
	for _, cmd := range cmds {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

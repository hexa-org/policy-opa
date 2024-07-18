package commandSupport

import (
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

func AssertContains(t *testing.T, url string, contains string) {
	resp, _ := http.Get(url)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), contains, url)
}

func MakeCmd(cmdString string, envs []string) (*exec.Cmd, io.ReadCloser) {
	_, file, _, _ := runtime.Caller(0)
	path := filepath.Join(file, "../../../")
	commandPath := filepath.Join(path, cmdString)

	var args []string

	args = append([]string{commandPath}, args...)
	// args = append([]string{"-coverprofile=c.out"}, args...)
	args = append([]string{"run"}, args...)

	cmd := exec.Command("go", args...)
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, envs...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}

	// assigning parent and child processes to a process group to ensure all process receive stop signal
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	return cmd, stdout
}

func StartCmd(cmd *exec.Cmd, checkPort int) error {
	log.Printf("Starting cmd %v\n", cmd)
	var err error
	if checkPort > 0 {
		err = cmd.Start()
		if err != nil {
			return err
		}
		WaitForHealthy(fmt.Sprintf("localhost:%v", checkPort))
	} else {

		cmd.WaitDelay = 30 * time.Second
		err = cmd.Run()
		if err != nil {
			return err
		}
		err = cmd.Wait()
	}
	return err
}

func WaitForHealthy(address string) {
	var isLive bool
	for !isLive {
		resp, err := http.Get(fmt.Sprintf("http://%s/health", address))
		if err == nil && resp.StatusCode == http.StatusOK {
			log.Println("Server is healthy.", address)
			isLive = true
		}
	}
}

func StopCmds(cmds ...*exec.Cmd) {
	for _, cmd := range cmds {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

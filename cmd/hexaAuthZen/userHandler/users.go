package userHandler

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/hexa-org/policy-opa/api/infoModel"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/config"
)

const DefaultUserPipFile string = "../resources/users.json"

var ulog = log.New(os.Stdout, "USERPIP: ", log.Ldate|log.Ltime)

// NewUserPIP Loads the AuthZen users and returns a UserIP map. If file is not found nil is returned.
func NewUserPIP(userPath string) *infoModel.UserRecs {
	loadFile := userPath
	var exists bool
	if userPath == "" {
		loadFile, exists = os.LookupEnv(config.EnvAuthUserPipFile)
		if !exists {
			_, file, _, _ := runtime.Caller(0)
			userPath := filepath.Join(file, "../", DefaultUserPipFile)
			loadFile = userPath
		}
	}
	userBytes, err := os.ReadFile(loadFile)
	if err != nil {
		ulog.Println(fmt.Sprintf("Error reading user info file: %s", err.Error()))
		return nil
	}

	var users infoModel.UserRecs
	err = json.Unmarshal(userBytes, &users)
	if err != nil {
		ulog.Println(fmt.Sprintf("Error parsing user info file: %s", err.Error()))
		return nil
	}

	return &users
}

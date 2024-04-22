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

type UserIP struct {
	users map[string]infoModel.UserInfo
}

// NewUserPIP Loads the AuthZen users and returns a UserIP map. If file is not found nil is returned.
func NewUserPIP(userPath string) *UserIP {
	uip := UserIP{users: make(map[string]infoModel.UserInfo)}
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

	for _, user := range users.Users {
		uip.users[user.Sub] = user
	}
	return &uip
}

func (u *UserIP) GetUser(id string) infoModel.UserInfo {
	return u.users[id]
}

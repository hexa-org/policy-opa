package userHandler

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/hexa-org/policy-opa/api/infoModel"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/config"
)

const DefaultUserPipFile string = "../resources/users.json"

var ulog = log.New(os.Stdout, "USERPIP: ", log.Ldate|log.Ltime)

type UserIP struct {
	users map[string]infoModel.UserInfo
}

func NewUserPIP(filepath string) *UserIP {
	uip := UserIP{users: make(map[string]infoModel.UserInfo)}
	loadFile := filepath
	var exists bool
	if filepath == "" {
		loadFile, exists = os.LookupEnv(config.EnvAuthUserPipFile)
		if !exists {
			loadFile = DefaultUserPipFile
		}
	}
	userBytes, err := os.ReadFile(loadFile)
	if err != nil {
		ulog.Println(fmt.Sprintf("Error reading user info file: %s", err.Error()))
		return &uip
	}

	var users infoModel.UserRecs
	err = json.Unmarshal(userBytes, &users)
	if err != nil {
		ulog.Println(fmt.Sprintf("Error parsing user info file: %s", err.Error()))
		return &uip
	}

	for _, user := range users.Users {
		uip.users[user.Sub] = user
	}
	return &uip
}

func (u *UserIP) GetUser(id string) infoModel.UserInfo {
	return u.users[id]
}

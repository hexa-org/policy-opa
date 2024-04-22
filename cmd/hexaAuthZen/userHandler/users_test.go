package userHandler

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/config"
	"github.com/stretchr/testify/assert"
)

func TestUsers(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	userPath := filepath.Join(file, "../", DefaultUserPipFile)
	wrongPath := filepath.Join(file, "../", "../resources", "wrong.json")

	badFile := filepath.Join(file, "../test/badUser.json")
	badDef := NewUserPIP(badFile)
	assert.Nil(t, badDef, "Should be parsing error")

	userDef := NewUserPIP("")
	assert.NotNil(t, userDef, "Default users not nil")
	assert.Equal(t, len(userDef.users), 5, "5 users loaded")

	users := NewUserPIP(wrongPath)
	assert.Nil(t, users, "Should be no userpip returned")

	users = NewUserPIP(userPath)
	assert.NotNil(t, users, "Should be a user pip loaded")
	assert.Greater(t, len(users.users), 4, "Should be at least 5 users")

	_ = os.Setenv(config.EnvAuthUserPipFile, userPath)
	usersByEnv := NewUserPIP("")
	assert.NotNil(t, usersByEnv, "Should be a user pip loaded")
	assert.Greater(t, len(usersByEnv.users), 4, "Should be at least 5 users")

	morty := users.GetUser("CiRmZDE2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs")
	assert.NotNil(t, morty, "Morty is returned")
	assert.Equal(t, "Morty Smith", morty.Name)
}

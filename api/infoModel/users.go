package infoModel

type UserInfo struct {
	Id      string   `json:"id"`
	Name    string   `json:"name"`
	Email   string   `json:"email"`
	Roles   []string `json:"roles"`
	Picture string   `json:"picture"`
}

type UserRecs map[string]UserInfo

func (u UserRecs) GetUser(id string) *UserInfo {
	user, exist := u[id]
	if !exist {
		return nil
	}
	return &user
}

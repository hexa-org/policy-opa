package infoModel

type UserInfo struct {
	Sub     string   `json:"sub"`
	Id      string   `json:"id"`
	Name    string   `json:"name"`
	Email   string   `json:"email"`
	Roles   []string `json:"roles"`
	Picture string   `json:"picture"`
}

type UserRecs struct {
	Users []UserInfo `json:"users"`
}

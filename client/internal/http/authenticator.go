package http

import (
	"encoding/json"
	"net/http"
)

type UserInfo struct {
	Sub               string   `json:"sub"`
	Name              string   `json:"name"`
	GivenName         string   `json:"given_name"`
	PreferredUsername string   `json:"preferred_username"`
	FamilyName        string   `json:"family_name"`
	Locale            string   `json:"locale"`
	ZoneInfo          string   `json:"zone_info"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"email_verified"`
	UpdatedAt         int      `json:"updated_at"`
	Groups            []string `json:"groups"`
}

func (u UserInfo) String() string {
	info, _ := json.Marshal(&u)
	return string(info)
}

type Authenticator interface {
	Login(rw http.ResponseWriter, r *http.Request)
	CallbackHandler(rw http.ResponseWriter, r *http.Request)
	IsAuthenticated(r *http.Request) bool
	UserInfo(r *http.Request) (UserInfo, error)
	GetAccessToken(r *http.Request) (string, error)
	GetIDToken(r *http.Request) (string, error)
}

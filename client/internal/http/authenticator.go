package http

import "net/http"

type UserInfo map[string]string

type Authenticator interface {
	Login(rw http.ResponseWriter, r *http.Request)
	CallbackHandler(rw http.ResponseWriter, r *http.Request)
	IsAuthenticated(r *http.Request) bool
	UserInfo(r *http.Request) (UserInfo, error)
}

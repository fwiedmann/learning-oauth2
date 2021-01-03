package http

import (
	"html/template"
	"net/http"

	"github.com/gorilla/mux"
)

func InitServer(a Authenticator) *Server {
	r := mux.NewRouter()
	s := &Server{
		s: &http.Server{
			Handler: r,
			Addr:    ":8080",
		},
		auth: a,
		tpl:  template.Must(template.ParseGlob("client/internal/http/html/*")),
	}

	r.HandleFunc("/login", CorsMiddleware(a.Login))
	r.HandleFunc("/authorization-code/callback", CorsMiddleware(a.CallbackHandler))
	r.HandleFunc("/", CorsMiddleware(s.rootHandler))

	return s
}

type customData struct {
	IsAuthenticated bool
	DisplayName     string
	AccessToken     string
	IDToken         string
	UserInfo        UserInfo
}

func (s *Server) rootHandler(rw http.ResponseWriter, r *http.Request) {
	var data customData
	data.IsAuthenticated = s.auth.IsAuthenticated(r)
	if !data.IsAuthenticated {
		s.tpl.ExecuteTemplate(rw, "root.html", data)
		return
	}

	info, err := s.auth.UserInfo(r)
	if err != nil {
		http.Error(rw, "could not fetch user Information: "+err.Error(), http.StatusInternalServerError)
		return
	}
	data.UserInfo = info
	data.DisplayName = info.Name

	accessToken, err := s.auth.GetAccessToken(r)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}
	data.AccessToken = accessToken

	idToken, err := s.auth.GetIDToken(r)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}
	data.IDToken = idToken
	s.tpl.ExecuteTemplate(rw, "root.html", data)
}

type Server struct {
	s    *http.Server
	auth Authenticator
	tpl  *template.Template
}

func (s *Server) Listen() error {
	return s.s.ListenAndServe()
}

func CorsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Access-Control-Allow-Origin", "http://localhost:8080")
		rw.Header().Set("Access-Control-Allow-Credentials", "true")
		next.ServeHTTP(rw, r)
	}
}

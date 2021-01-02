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
		Authenticator: a,
		tpl:           template.Must(template.ParseGlob("client/internal/http/html/*")),
	}

	r.HandleFunc("/login", CorsMiddleware(a.Login))
	r.HandleFunc("/authorization-code/callback", CorsMiddleware(a.CallbackHandler))
	r.HandleFunc("/", CorsMiddleware(s.rootHandler))

	return s
}

type customData struct {
	IsAuthenticated bool
	DisplayName     string
}

func (s *Server) rootHandler(rw http.ResponseWriter, r *http.Request) {
	var data customData
	data.IsAuthenticated = s.Authenticator.IsAuthenticated(r)
	if data.IsAuthenticated {
		data.DisplayName = s.Authenticator.UserInfo(r)["name"]
	}

	s.tpl.ExecuteTemplate(rw, "root.html", data)
}

type Server struct {
	s *http.Server
	Authenticator
	tpl *template.Template
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

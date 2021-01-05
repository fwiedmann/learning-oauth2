package http

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

type Server struct {
	s          *http.Server
	auth       Authenticator
	tpl        *template.Template
	backendURL string
}

func (s *Server) Listen() error {
	return s.s.ListenAndServe()
}

func InitServer(backendURL string, a Authenticator) *Server {
	r := mux.NewRouter()
	s := &Server{
		s: &http.Server{
			Handler: r,
			Addr:    ":8080",
		},
		auth:       a,
		tpl:        template.Must(template.ParseGlob("client/internal/http/html/*")),
		backendURL: backendURL,
	}

	r.HandleFunc("/login", CorsMiddleware(a.Login))
	r.HandleFunc("/authorization-code/callback", CorsMiddleware(a.CallbackHandler))
	r.HandleFunc("/", CorsMiddleware(s.rootHandler))

	return s
}

type customData struct {
	IsAuthenticated    bool
	DisplayName        string
	AccessToken        string
	AccessTokenPayload string
	IDToken            string
	IDTokenPayload     string
	UserInfo           UserInfo
	Books              []Book
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
		return
	}
	data.AccessToken = accessToken

	atPayload, _ := base64.URLEncoding.DecodeString(strings.Split(accessToken, ".")[1])
	data.AccessTokenPayload = string(atPayload)

	idToken, err := s.auth.GetIDToken(r)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	data.IDToken = idToken

	idtPayload, err := base64.URLEncoding.DecodeString(strings.Split(idToken, ".")[1])
	data.IDTokenPayload = string(idtPayload)

	books, err := s.listBooks(s.backendURL, accessToken)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	data.Books = books

	s.tpl.ExecuteTemplate(rw, "root.html", data)
}

type Book struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func (s *Server) listBooks(backendURL, auth string) ([]Book, error) {
	r, err := http.NewRequest(http.MethodGet, backendURL+"/books", nil)
	if err != nil {
		return nil, err
	}

	r.Header.Add("Authorization", "Bearer "+auth)
	r.Header.Add("Accept", "application/json")

	c := &http.Client{}
	resp, err := c.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("response code of backend is not 200: %d", resp.StatusCode)
	}

	var books []Book
	if err := json.NewDecoder(resp.Body).Decode(&books); err != nil {
		return nil, err
	}
	return books, nil
}

func CorsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Access-Control-Allow-Origin", "http://localhost:8080")
		rw.Header().Set("Access-Control-Allow-Credentials", "true")
		next.ServeHTTP(rw, r)
	}
}

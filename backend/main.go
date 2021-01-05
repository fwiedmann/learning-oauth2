package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/mux"

	verifier "github.com/okta/okta-jwt-verifier-golang"
)

var issuer string

func main() {
	issuer = os.Getenv("OKTA_ISSUER")
	if issuer == "" {
		panic("required OKTA_ISSUER environment variable is empty")
	}
	r := mux.NewRouter()
	r.HandleFunc("/books", checkIsAuthenticated(listBooks))
	panic(http.ListenAndServe(":8081", r))
}

func checkIsAuthenticated(next http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if auth == "" {
			http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		claims := map[string]string{"aud": "testing-client"}
		jv := verifier.JwtVerifier{
			Issuer:           issuer,
			ClaimsToValidate: claims,
		}

		if _, err := jv.New().VerifyAccessToken(auth); err != nil {
			http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		if !tokenHasRequiredGroups(auth, "Everyone", "Admin") {
			http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(rw, r)
	}
}

type Book struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func listBooks(rw http.ResponseWriter, _ *http.Request) {
	var books []Book
	for i := 0; i < 10; i++ {
		books = append(books, Book{ID: i, Name: fmt.Sprintf("book-name-%d", i)})
	}

	json.NewEncoder(rw).Encode(books)
}

type Payload struct {
	Groups []string `json:"groups"`
}

func tokenHasRequiredGroups(token string, groups ...string) bool {
	s := strings.Split(token, ".")[1]
	payload, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return false
	}

	var pl Payload
	if err := json.Unmarshal(payload, &pl); err != nil {
		return false
	}

	for _, group := range groups {
		var found bool
		for _, plGroup := range pl.Groups {
			if group == plGroup {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

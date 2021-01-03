package main

import (
	"os"

	"github.com/fwiedmann/learning-oauth2/client/internal/http"
)

func main() {
	panic(http.InitServer(os.Getenv("BACKEND_URL"), http.NewOktaAuthenticator(os.Getenv("OKTA_CLIENT_ID"), os.Getenv("OKTA_CLIENT_SECRET"), os.Getenv("OKTA_ISSUER"), os.Getenv("ENCRYPTION_KEY"))).Listen())
}

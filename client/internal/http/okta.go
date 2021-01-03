package http

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"

	"github.com/gorilla/sessions"

	verifier "github.com/okta/okta-jwt-verifier-golang"
)

const (
	oktaSessionStoreKey = "okta-hosted-login-session-store"
	oktaSessionStateKey = "okta-hosted-login-state"
)

func NewOktaAuthenticator(clientID, clientSecret, issuer, cookieEncryptionKey string) *OktaAuthenticator {
	store := sessions.NewCookieStore([]byte(cookieEncryptionKey))
	store.Options.HttpOnly = true
	return &OktaAuthenticator{
		clientID:     clientID,
		clientSecret: clientSecret,
		issuer:       issuer,
		store:        store,
	}
}

type OktaAuthenticator struct {
	clientID     string
	clientSecret string
	issuer       string
	store        sessions.Store
}

func (o *OktaAuthenticator) IsAuthenticated(r *http.Request) bool {
	s, err := o.store.Get(r, oktaSessionStoreKey)
	if err != nil {
		panic(err)
	}

	idToken, ok := s.Values["id_token"]
	if !ok {
		return false
	}

	idTokenString, ok := idToken.(string)
	if !ok {
		return false
	}

	if _, err := o.verifyIDToken(idTokenString, r); err != nil {
		return false
	}

	accessToken, ok := s.Values["access_token"]
	if !ok {
		return false
	}

	accessTokenString, ok := accessToken.(string)
	if !ok {
		return false
	}

	if _, err := o.verifyAccessToken(accessTokenString); err != nil {
		return false
	}

	fmt.Printf("this is the id_token:\n%s\nthis is the acces_token:\n%s\n", s.Values["id_token"], s.Values["access_token"])
	return true
}

func (o *OktaAuthenticator) UserInfo(r *http.Request) (UserInfo, error) {
	session, err := o.store.Get(r, oktaSessionStoreKey)

	if err != nil || session.Values["access_token"] == nil || session.Values["access_token"] == "" {
		return UserInfo{}, err
	}

	reqUrl := o.issuer + "/v1/userinfo"

	req, _ := http.NewRequest("GET", reqUrl, bytes.NewReader([]byte("")))
	h := req.Header
	h.Add("Authorization", "Bearer "+session.Values["access_token"].(string))
	h.Add("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return UserInfo{}, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return UserInfo{}, err
	}

	fmt.Print(string(body))
	defer resp.Body.Close()
	var info UserInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return UserInfo{}, err
	}
	return info, nil
}

func (o *OktaAuthenticator) Login(rw http.ResponseWriter, r *http.Request) {
	var redirectPath string

	randomState := generateRandomStrings(10)
	randomNonce := generateRandomStrings(10)
	session, _ := o.store.Get(r, oktaSessionStateKey)
	session.Values["state"] = randomState
	session.Values["nonce"] = randomNonce

	if err := session.Save(r, rw); err != nil {
		http.Error(rw, "Could not save state", http.StatusInternalServerError)
	}

	q := r.URL.Query()
	q.Add("client_id", o.clientID)
	q.Add("response_type", "code")
	q.Add("response_mode", "query")
	q.Add("scope", "openid profile email groups")
	q.Add("redirect_uri", "http://localhost:8080/authorization-code/callback")
	q.Add("state", randomState)
	q.Add("nonce", randomNonce)

	redirectPath = o.issuer + "/v1/authorize?" + q.Encode()
	http.Redirect(rw, r, redirectPath, http.StatusTemporaryRedirect)
}

func (o *OktaAuthenticator) CallbackHandler(rw http.ResponseWriter, r *http.Request) {
	stateSession, _ := o.store.Get(r, oktaSessionStateKey)

	if r.URL.Query().Get("state") != stateSession.Values["state"] {
		http.Error(rw, "The state was not as expected", http.StatusInternalServerError)
		return
	}
	// Make sure the code was provided
	if r.URL.Query().Get("code") == "" {
		http.Error(rw, "The code was not returned or is not accessible", http.StatusInternalServerError)
		return
	}

	exchange, err := o.exchangeCode(r.URL.Query().Get("code"), r)
	if err != nil {
		http.Error(rw, "Could not exchange code", http.StatusInternalServerError)
	}

	session, err := o.store.Get(r, "okta-hosted-login-session-store")
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	_, verificationError := o.verifyIDToken(exchange.IdToken, r)
	if verificationError != nil {
		fmt.Println(verificationError)
	}

	_, verificationError = o.verifyAccessToken(exchange.AccessToken)
	if verificationError != nil {
		fmt.Println(verificationError)
	}

	if verificationError == nil {
		session.Values["id_token"] = exchange.IdToken
		session.Values["access_token"] = exchange.AccessToken
		if err := session.Save(r, rw); err != nil {
			panic(err)
		}
	}

	http.Redirect(rw, r, "/", http.StatusTemporaryRedirect)
}

type Exchange struct {
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	AccessToken      string `json:"access_token,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
	ExpiresIn        int    `json:"expires_in,omitempty"`
	Scope            string `json:"scope,omitempty"`
	IdToken          string `json:"id_token,omitempty"`
}

func (o *OktaAuthenticator) exchangeCode(code string, r *http.Request) (Exchange, error) {
	authHeader := base64.StdEncoding.EncodeToString(
		[]byte(o.clientID + ":" + o.clientSecret))

	q := r.URL.Query()
	q.Add("grant_type", "authorization_code")
	q.Add("code", code)
	q.Add("redirect_uri", "http://localhost:8080/authorization-code/callback")

	url := o.issuer + "/v1/token?" + q.Encode()

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return Exchange{}, err
	}

	h := req.Header
	h.Add("Authorization", "Basic "+authHeader)
	h.Add("Accept", "application/json")
	h.Add("Content-Type", "application/x-www-form-urlencoded")
	h.Add("Connection", "close")
	h.Add("Content-Length", "0")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return Exchange{}, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return Exchange{}, err
	}

	var exchange Exchange
	if err := json.Unmarshal(body, &exchange); err != nil {
		return Exchange{}, err
	}

	return exchange, nil
}

func (o *OktaAuthenticator) verifyIDToken(t string, r *http.Request) (*verifier.Jwt, error) {
	session, err := o.store.Get(r, "okta-hosted-login-state")
	if err != nil {
		return nil, err
	}

	tv := map[string]string{}
	tv["nonce"] = session.Values["nonce"].(string)
	tv["aud"] = o.clientID
	jv := verifier.JwtVerifier{
		Issuer:           o.issuer,
		ClaimsToValidate: tv,
	}

	result, err := jv.New().VerifyIdToken(t)
	if err != nil {
		return nil, fmt.Errorf("%s", err)
	}

	if result != nil {
		return result, nil
	}

	return nil, fmt.Errorf("token could not be verified: %s", "")
}

func (o *OktaAuthenticator) verifyAccessToken(t string) (*verifier.Jwt, error) {
	tv := map[string]string{}
	tv["aud"] = "testing-client"
	jv := verifier.JwtVerifier{
		Issuer:           o.issuer,
		ClaimsToValidate: tv,
	}

	result, err := jv.New().VerifyAccessToken(t)
	if err != nil {
		return nil, fmt.Errorf("%s", err)
	}

	if result != nil {
		return result, nil
	}

	return nil, fmt.Errorf("token could not be verified: %s", "")
}

func (o *OktaAuthenticator) GetAccessToken(r *http.Request) (string, error) {
	stateSession, err := o.store.Get(r, oktaSessionStoreKey)
	if err != nil {
		return "", err
	}
	return stateSession.Values["access_token"].(string), err
}

func (o *OktaAuthenticator) GetIDToken(r *http.Request) (string, error) {
	stateSession, err := o.store.Get(r, oktaSessionStoreKey)
	if err != nil {
		return "", err
	}
	return stateSession.Values["id_token"].(string), err
}

var letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func generateRandomStrings(l int) string {
	state := make([]byte, l)
	for b := range state {
		state[b] = letters[rand.Intn(len(letters))]
	}
	return string(state)
}

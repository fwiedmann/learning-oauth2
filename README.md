# learning-oauth2

I want to learn how to use the oauth2 Authorization Code Flow in Go. The example code is based on the [github.com/okta/samples-golang/tree/develop/okta-hosted-login](https://github.com/okta/samples-golang/tree/develop/okta-hosted-login) repository and modified for an production ready example.


## OAUTH 2 / OIDC Authorization Code Flow

### Login

The first step of the Authorization Code Flow is to redirect the user to the OIDC provider (also called the issuer) login page. Your application has to send the following required parameters in order to proceed the login.

These are the query parameters:

- `client_id`: The ID of the used client which is configured/present at the issuers site.
- `response_type`: Tells the authorization server which grant to execute. For the Authorization Code grant, use response_type=code to include the authorization code. For the Implicit grant, use response_type=token to include an access token. An alternative is to use response_type=id_token token to include both an access token and an ID token.
- `response_mode`: (Optional) How the result of the authorization request is formatted.
- `scope`: A space-delimited list of permissions that the application requires.
- `state`: An opaque value, used for security purposes. If this request parameter is set in the request, then it is returned to the application as part of the redirect_uri. The state has to be verified by the call-back handler.
- `redirect_uri`: Holds a URL. A successful response from this endpoint results in a redirect to this URL.
- `nonce`: The nonce will be added into the access token as a claim and should be verified by the server.

### Call-Back

After a user successfully logged in, the issuer will redirect the user to the defined `redirect_url`. The issuer added the following query parameters to the redirect request which will be used to exchange an valid `access_token` and `ìd_token`:

- `code`: This is short living token which will be used to request the issuers `token endpoint` to issue an `access_token` and `ìd_token`.
- `state`: This string has be the same as the `state` send in the previous request to the issuer. If the state values differs the auth flow should be aborted due to integrity is not given.

When requesting the `token endpoint` of the issuer via a POST request in order to get an `access_token` and `ìd_token` the following headers & query parameter are required:

- `grant_type` query parameter: The Authorization Code grant type is used by confidential and public clients to exchange an authorization code for an access token.
- `code` query parameter: Its the short living token provided by the issuer. In combination with the `client_id` and `client_secret` the issuer can validate the request and is able to issue the correct `access_token` and `ìd_token` for the user.
- `redirect_uri` parameter: The value of the redirect_uri parameter included in the original authentication request.
- `Authorization Basic <CLIENT_ID:CLIENT_SECRET>` header: Setting a authorization header to verify the applications identity.
- `Content-Type application/x-www-form-urlencoded` header: Tells the server to lookup the http query parameters for the required information

On a successful request the issuer response with the `access_token`, `id_token` and other additional information:

```go
type Exchange struct {
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	AccessToken      string `json:"access_token,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
	ExpiresIn        int    `json:"expires_in,omitempty"`
	Scope            string `json:"scope,omitempty"`
	IdToken          string `json:"id_token,omitempty"`
}
```

### Token Validation

Both received tokens have to validated by the server. Please read the following for more details:

- [validate id tokens](https://auth0.com/docs/tokens/id-tokens/validate-id-tokens)
- [validate access tokens](https://auth0.com/docs/tokens/access-tokens/validate-access-tokens)

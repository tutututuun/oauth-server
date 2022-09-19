package main

import "html/template"

const (
	//SCOPE                 = "readonly"
	SCOPE                  = "https://www.googleapis.com/auth/photoslibrary.readonly"
	AUTH_CODE_DURATION     = 300
	ACCESS_TOKEN_DURATION  = 3600
	REFRESH_TOKEN_DURATION = 3600 * 24 * 30
)

type Client struct {
	id          string
	name        string
	redirectURL string
	secret      string
}

type User struct {
	id          int
	name        string
	password    string
	sub         string
	name_ja     string
	given_name  string
	family_name string
	locale      string
}

type Session struct {
	client                string
	state                 string
	scopes                string
	redirectUri           string
	code_challenge        string
	code_challenge_method string
	// OIDC用
	nonce string
	// IDトークンを払い出すか否か、trueならIDトークンもfalseならOAuthでトークンだけ払い出す
	oidc bool
}

type AuthCode struct {
	user         string
	clientId     string
	scopes       string
	redirect_uri string
	expires_at   int64
}

type TokenCode struct {
	user               string
	clientId           string
	scopes             string
	expires_at         int64
	refresh_expires_at int64
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IdToken      string `json:"id_token,omitempty"`
}

type Payload struct {
	Iss        string `json:"iss"`
	Azp        string `json:"azp"`
	Aud        string `json:"aud"`
	Sub        string `json:"sub"`
	AtHash     string `json:"at_hash"`
	Nonce      string `json:"nonce"`
	Name       string `json:"name"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
	Locale     string `json:"locale"`
	Iat        int64  `json:"iat"`
	Exp        int64  `json:"exp"`
}

var templates = template.Must(template.ParseFiles("login.html"))
var sessionList = make(map[string]Session)
var AuthCodeList = make(map[string]AuthCode)
var TokenCodeList = make(map[string]TokenCode)
var RefreshTokenList = make(map[string]TokenCode)

// クライアント情報をハードコード
var clientInfo = Client{
	id:          "1234",
	name:        "test",
	redirectURL: "http://localhost:8080/callback",
	secret:      "secret",
}

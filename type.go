package main

import (
	"errors"
	"fmt"
	"html/template"
	"log"
	"time"
)

const (
	SCOPE                  = "read"
	AUTH_CODE_DURATION     = 300
	ACCESS_TOKEN_DURATION  = 60
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
	err          error
}

type TokenCode struct {
	user               string
	clientId           string
	scopes             string
	create_at          int64
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

type JWT struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type Payload struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Jti string `json:"jti"`
}

var templates = template.Must(template.ParseFiles("login.html"))
var sessionList = make(map[string]Session)
var AuthCodeList = make(map[string]AuthCode)
var TokenCodeList = make(map[string]TokenCode)
var RefreshTokenList = make(map[string]TokenCode)

func (authCode *AuthCode) matchClientID(clientID string) {
	if authCode.err != nil {
		return
	}
	if authCode.clientId != clientID {
		log.Println("client_id not match")
		authCode.err = errors.New("invalid_request. client_id not match.")
	}
	return
}

func (authCode *AuthCode) matchRedirect_uri(redirect_uri string) {
	if authCode.err != nil {
		return
	}
	if authCode.redirect_uri != redirect_uri {
		log.Println("redirect_uri not match")
		authCode.err = errors.New("invalid_request. redirect_uri not match.")
	}
	return
}

func (authCode *AuthCode) chkExpires_at() {
	if authCode.err != nil {
		return
	}
	if authCode.expires_at < time.Now().Unix() {
		log.Println("authcode expired")
		authCode.err = errors.New("invalid_request. auth code time limit is expire.")
	}
	return
}

func (session *Session) verifyCodeChallenge(code_verifier string) error {
	var code_challenge string
	if session.code_challenge_method == "plain" {
		code_challenge = code_verifier
	} else if session.code_challenge_method == "S256" {
		code_challenge = base64URLEncode(code_verifier)
	} else {
		log.Println("code_challenge is not match.")
		return errors.New(fmt.Sprintf("invalid_request. code_challenge is not match.\n"))
	}
	if session.code_challenge != code_challenge {
		return errors.New("PKCE check is err...")
	}
	return nil
}

// クライアントのクレデンシャル(ハードコード)
var clientInfo = Client{
	id:          "1234",
	name:        "test",
	redirectURL: "http://localhost:10080/callback",
	secret:      "secret",
}

//保護対象リソースのクレデンシャル(ハードコード)
type ProtectedResource struct {
	id      string
	sercret string
}

var protectedResourceInfo = ProtectedResource{
	id:      "abcd",
	sercret: "terces",
}

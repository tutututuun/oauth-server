package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
)

func authHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	session := Session{
		client:      query.Get("client_id"),
		state:       query.Get("state"),
		scopes:      query.Get("scope"),
		redirectUri: query.Get("redirect_uri"),
	}

	requiredParameter := []string{"response_type", "client_id", "redirect_uri"}
	w, ok := checkParameter(query, requiredParameter, w)
	if !ok {
		return
	}

	if clientInfo.id != query.Get("client_id") {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("client_id is not match"))
		return
	}
	// レスポンスタイプはいったん認可コードだけをサポート
	if "code" != query.Get("response_type") {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("only support code"))
		return
	}
	sessionId := uuid.New().String()
	sessionList[sessionId] = session

	cookie := &http.Cookie{
		Name:  "session",
		Value: sessionId,
	}
	http.SetCookie(w, cookie)

	renderTemplate(w, "login", struct {
		ClientId string
		Scope    string
	}{
		ClientId: session.client,
		Scope:    session.scopes,
	})

	log.Println("return login page...")
}

func authCheckHandler(w http.ResponseWriter, r *http.Request) {
	loginUser := r.FormValue("username")
	password := r.FormValue("password")

	//ToDo: ユーザ情報はハードコーディング
	if loginUser != user.name || password != user.password {
		w.Write([]byte("login failed"))
	} else {
		cookie, _ := r.Cookie("session")
		http.SetCookie(w, cookie)
		v, _ := sessionList[cookie.Value]

		authCodeString := uuid.New().String()
		authData := AuthCode{
			user:         loginUser,
			clientId:     v.client,
			scopes:       v.scopes,
			redirect_uri: v.redirectUri,
			expires_at:   time.Now().Unix() + 300,
		}

		AuthCodeList[authCodeString] = authData

		log.Printf("auth code accepet : %s\n", authData)

		location := fmt.Sprintf("%s?code=%s&state=%s", v.redirectUri, authCodeString, v.state)
		w.Header().Add("Location", location)
		w.WriteHeader(302)

	}
}

func tokenHandler(w http.ResponseWriter, req *http.Request) {
	cookie, _ := req.Cookie("session")
	req.ParseForm()
	query := req.Form
	session := sessionList[cookie.Value]

	requiredParameter := []string{"grant_type"}
	w, okParam := checkParameter(query, requiredParameter, w)
	if !okParam {
		return
	}
	tokenInfo := TokenCode{}
	switch query.Get("grant_type") {
	case "authorization_code":
		requiredParameter := []string{"code", "client_id", "redirect_uri"}
		w, okParam := checkParameter(query, requiredParameter, w)
		if !okParam {
			return
		}
		v, okCode := AuthCodeList[query.Get("code")]
		if !okCode {
			log.Println("auth code isn't exist")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(fmt.Sprintf("no authrization code")))
			return
		}

		if v.clientId != query.Get("client_id") {
			log.Println("client_id not match")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(fmt.Sprintf("invalid_request. client_id not match.\n")))
			return
		}

		if v.redirect_uri != query.Get("redirect_uri") {
			log.Println("redirect_uri not match")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(fmt.Sprintf("invalid_request. redirect_uri not match.\n")))
			return
		}

		if v.expires_at < time.Now().Unix() {
			log.Println("authcode expire")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(fmt.Sprintf("invalid_request. auth code time limit is expire.\n")))
			return
		}

		if clientInfo.secret != query.Get("client_secret") {
			log.Println("client_secret is not match.")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(fmt.Sprintf("invalid_request. client_secret is not match.\n")))
			return
		}

		// PKCE
		if session.oidc == false && session.code_challenge != base64URLEncode(query.Get("code_verifier")) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("PKCE check is err..."))
			return
		}
		tokenInfo = createTokenInfo(v.user, v.clientId, v.scopes)
		// 認可コードを削除
		delete(AuthCodeList, query.Get("code"))
	case "refresh_token":
		requiredParameter := []string{"refresh_token"}
		w, okParam := checkParameter(query, requiredParameter, w)
		if !okParam {
			return
		}
		v, okReflesh := RefreshTokenList[query.Get("refresh_token")]
		if !okReflesh {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(fmt.Sprintf("invalid_request. refresh_token is not match.\n")))
			return
		}
		if v.refresh_expires_at < time.Now().Unix() {
			log.Println("authcode expire")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(fmt.Sprintf("invalid_request. Refresh toke time limit is expire.\n")))
			return
		}
		tokenInfo = createTokenInfo(v.user, v.clientId, v.scopes)
		//リフレッシュトークンを削除
		delete(RefreshTokenList, query.Get("refresh_token"))
	default:
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("invalid_request. not support type.\n")))
		return
	}

	tokenString := uuid.New().String()
	refreshTokenString := uuid.New().String()

	// 払い出したトークン情報を保存(DBではなく、メモリに保存)
	TokenCodeList[tokenString] = tokenInfo
	RefreshTokenList[refreshTokenString] = tokenInfo

	tokenResp := TokenResponse{
		AccessToken:  tokenString,
		TokenType:    "Bearer",
		ExpiresIn:    tokenInfo.expires_at,
		RefreshToken: refreshTokenString,
	}

	resp, err := json.Marshal(tokenResp)
	if err != nil {
		log.Println("json marshal err")
	}

	log.Printf("token ok to client %s, token is %s", tokenInfo.clientId, string(resp))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resp)

}

func main() {
	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/authcheck", authCheckHandler)
	http.HandleFunc("/token", tokenHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

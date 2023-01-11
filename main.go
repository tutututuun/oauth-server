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

	requiredParameters := []string{"response_type", "client_id", "redirect_uri", "code_challenge", "code_challenge_method"}
	if !hasParameters(query, requiredParameters, w) {
		return
	}

	if clientInfo.id != query.Get("client_id") {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("client_id is not match"))
		return
	}

	if "code" != query.Get("response_type") {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("only support code"))
		return
	}
	session := Session{
		client:                query.Get("client_id"),
		state:                 query.Get("state"),
		scopes:                query.Get("scope"),
		redirectUri:           query.Get("redirect_uri"),
		code_challenge:        query.Get("code_challenge"),
		code_challenge_method: query.Get("code_challenge_method"),
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
			err:          nil,
		}

		AuthCodeList[authCodeString] = authData

		log.Printf("auth code accepet : %s\n", authData)

		location := fmt.Sprintf("%s?code=%s&state=%s", v.redirectUri, authCodeString, v.state)
		w.Header().Add("Location", location)
		w.WriteHeader(302)

	}
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	query := r.Form
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		log.Println("client not match")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("invalid_request. client not match.\n")))
		return
	}

	requiredParameter := []string{"grant_type"}
	if !hasParameters(query, requiredParameter, w) {
		return
	}
	tokenInfo := TokenCode{}
	switch query.Get("grant_type") {
	case "authorization_code":
		cookie, _ := r.Cookie("session")
		session, ok := sessionList[cookie.Value]
		if !ok {
			log.Println("Invalid session")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(fmt.Sprintf("invalid_request. Invalid session.\n")))
			return
		}
		requiredParameter := []string{"code", "redirect_uri", "code_verifier"}
		if !hasParameters(query, requiredParameter, w) {
			return
		}
		v, ok := AuthCodeList[query.Get("code")]
		if !ok {
			log.Println("auth code isn't exist")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(fmt.Sprintf("no authrization code")))
			return
		}

		v.matchClientID(clientID)
		v.matchRedirect_uri(query.Get("redirect_uri"))
		v.chkExpires_at()
		if v.err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(fmt.Sprintf("%s\n", v.err.Error())))
			return
		}

		if clientInfo.secret != clientSecret {
			log.Println("client_secret is not match.")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(fmt.Sprintf("invalid_request. client_secret is not match.\n")))
			return
		}
		if err := session.verifyCodeChallenge(query.Get("code_verifier")); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}
		tokenInfo = createTokenInfo(v.user, v.clientId, v.scopes)
		delete(AuthCodeList, query.Get("code"))
	case "refresh_token":
		requiredParameters := []string{"refresh_token"}
		if !hasParameters(query, requiredParameters, w) {
			return
		}
		v, okRefresh := RefreshTokenList[query.Get("refresh_token")]
		if !okRefresh {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(fmt.Sprintf("invalid_request. refresh_token is not match.\n")))
			return
		}
		if v.clientId != clientID {
			log.Println("client_id not match")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(fmt.Sprintf("invalid_request. client_id not match.\n")))
			//不正アクセスが考えられるためトークンを削除
			delete(RefreshTokenList, query.Get("refresh_token"))
			return
		}
		if clientInfo.secret != clientSecret {
			log.Println("client_secret is not match.")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(fmt.Sprintf("invalid_request. client_secret is not match.\n")))
			//不正アクセスが考えられるためトークンを削除
			delete(RefreshTokenList, query.Get("refresh_token"))
			return
		}
		if v.refresh_expires_at < time.Now().Unix() {
			log.Println("authcode expire")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(fmt.Sprintf("invalid_request. Refresh toke time limit is expire.\n")))
			//有効期限を過ぎているため、リフレッシュトークンを削除
			delete(RefreshTokenList, query.Get("refresh_token"))
			return
		}
		tokenInfo = createTokenInfo(v.user, v.clientId, v.scopes)
		//トークンとリフレッシュを再発行するため、現在のリフレッシュトークンを削除
		delete(RefreshTokenList, query.Get("refresh_token"))
	default:
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("invalid_request. not support type.\n")))
		return
	}

	//tokenString := uuid.New().String()
	tokenString := tokenInfo.createTokenStringBase64URLEncoding()
	TestRSAVerify(tokenString)

	refreshTokenString := uuid.New().String()

	// 払い出したトークン情報を保存(DBではなく、メモリに保存)
	TokenCodeList[tokenString] = tokenInfo
	RefreshTokenList[refreshTokenString] = tokenInfo

	// 払い出すトークン情報
	tokenResp := TokenResponse{
		AccessToken:  tokenString,
		TokenType:    "Bearer",
		ExpiresIn:    tokenInfo.expires_at,
		RefreshToken: refreshTokenString,
	}

	resp, _ := json.Marshal(tokenResp)

	log.Printf("token ok to client %s, token is %s", tokenInfo.clientId, string(resp))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resp)

}

func introspectHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	query := r.Form
	requiredParameters := []string{"token"}
	if !hasParameters(query, requiredParameters, w) {
		return
	}

	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		log.Println("client is not match")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("invalid_request. client not match.\n")))
		return
	}
	if clientID != protectedResourceInfo.id {
		log.Println("client id is not match")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("invalid_request. client id is not match.\n")))
		return
	}
	if clientSecret != protectedResourceInfo.sercret {
		log.Println("client secrer is not match")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("invalid_request. client secrer is not match.\n")))
		return
	}

	type _introspection struct {
		Active bool `json:"active"`
	}
	var introspectionResponse = _introspection{
		Active: false,
	}

	token := query.Get("token")
	if _, ok := TokenCodeList[token]; ok {
		introspectionResponse.Active = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp, _ := json.Marshal(introspectionResponse)
		w.Write(resp)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp, _ := json.Marshal(introspectionResponse)
	w.Write(resp)
	return
}

func revokeHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	query := r.Form
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		log.Println("client not match")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("invalid_request. client not match.\n")))
		return
	}

	requiredParameter := []string{"token"}
	if !hasParameters(query, requiredParameter, w) {
		return
	}

	//TODD: クライアント情報はDB登録してそこから取得することで複数クライアントに対応できる。
	//今回は1クライアントなので、ハードコーディング情報から取得
	if clientInfo.id != clientID {
		log.Println("client_id is not match")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("invalid_request. client_id not match.\n")))
		return
	}
	//TODO: 同上
	if clientInfo.secret != clientSecret {
		log.Println("client secret is not match")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("invalid_request. redirect_uri not match.\n")))
		return
	}

	token := query.Get("token")
	if _, ok := TokenCodeList[token]; ok {
		delete(TokenCodeList, token)
	}
	if _, ok := RefreshTokenList[token]; ok {
		delete(RefreshTokenList, token)
		//TODO: 関連するトークン情報を削除する処理をいれる。
	}
	// セキュリティのため、トークンの削除できたかに関係なく、
	// 正常に完了したこととする。
	w.WriteHeader(http.StatusOK)
	return
}

func main() {
	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/authcheck", authCheckHandler)
	http.HandleFunc("/token", tokenHandler)
	http.HandleFunc("/introspect", introspectHandler)
	http.HandleFunc("/revoke", revokeHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

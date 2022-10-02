package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"reflect"
	"time"
)

func base64URLEncode(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func renderTemplate(w http.ResponseWriter, tmpl string, value interface{}) {
	fv := reflect.ValueOf(value)
	err := templates.ExecuteTemplate(w, tmpl+".html", fv)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func checkParameter(query url.Values, param []string, w http.ResponseWriter) (http.ResponseWriter, bool) {
	for _, v := range param {
		if _, ok := query[v]; !ok {
			log.Printf("%s is missing", v)
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(fmt.Sprintf("invalid_request. %s is missing\n", v)))
			return w, false
		}
	}
	return w, true
}

func createTokenInfo(user string, clientId string, scopes string) TokenCode {
	nowTime := time.Now()
	tokenExpireTime := nowTime.Unix() + ACCESS_TOKEN_DURATION
	refreshTokenExpireTime := nowTime.Unix() + REFRESH_TOKEN_DURATION
	return TokenCode{
		user:               user,
		clientId:           clientId,
		scopes:             scopes,
		create_at:          nowTime.Unix(),
		expires_at:         tokenExpireTime,
		refresh_expires_at: refreshTokenExpireTime,
	}
}

func randomString(n int) string {
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

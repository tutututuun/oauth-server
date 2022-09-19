package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
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
	tokenExpireTime := time.Now().Unix() + ACCESS_TOKEN_DURATION
	refreshTokenExpireTime := time.Now().Unix() + REFRESH_TOKEN_DURATION
	return TokenCode{
		user:               user,
		clientId:           clientId,
		scopes:             scopes,
		expires_at:         tokenExpireTime,
		refresh_expires_at: refreshTokenExpireTime,
	}
}

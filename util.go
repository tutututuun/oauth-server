package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
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

func hasParameters(query url.Values, param []string, w http.ResponseWriter) bool {
	for _, v := range param {
		if _, ok := query[v]; !ok {
			log.Printf("%s is missing", v)
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(fmt.Sprintf("invalid_request. %s is missing\n", v)))
			return false
		}
	}
	return true
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

func readPrivateKey(path string) (*rsa.PrivateKey, error) {
	privateKeyData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	privateKeyBlock, _ := pem.Decode(privateKeyData)
	if privateKeyBlock == nil {
		return nil, errors.New("invalid private key data")
	}
	if privateKeyBlock.Type != "RSA PRIVATE KEY" {
		return nil, errors.New(fmt.Sprintf("invalid private key type : %s", privateKeyBlock.Type))
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, err
}

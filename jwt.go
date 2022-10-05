package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
)

var (
	ErrKeyMustBePEMEncoded = errors.New("Invalid Key: Key must be a PEM encoded PKCS1 or PKCS8 key")
	ErrNotRSAPrivateKey    = errors.New("Key is not a valid RSA private key")
	ErrNotRSAPublicKey     = errors.New("Key is not a valid RSA public key")

	ErrInvalidKey      = errors.New("key is invalid")
	ErrInvalidKeyType  = errors.New("key is of invalid type")
	ErrHashUnavailable = errors.New("the requested hash function is unavailable")
)

func (tokenInfo TokenCode) createTokenStringBase64URLEncoding() string {
	jwt := JWT{
		Typ: "JWT",
		Alg: "RS256",
	}
	jwt_b, _ := json.Marshal(jwt)
	jwt_str := base64.URLEncoding.EncodeToString(jwt_b)
	payload := Payload{
		Iss: "http://localhost:8080/",
		Sub: tokenInfo.user,
		Aud: "http://localhost:9000", //保護対象リソースを指定
		Iat: tokenInfo.create_at,
		Exp: tokenInfo.expires_at,
		Jti: randomString(8),
	}
	payload_b, _ := json.Marshal(payload)
	payload_str := base64.URLEncoding.EncodeToString(payload_b)
	privateKeyData, _ := ioutil.ReadFile(".ssh/id_rsa")
	pkey, _ := ParseRSAPrivateKeyFromPEM(privateKeyData)

	sig, _ := RSASign(jwt_str+"."+payload_str, pkey)
	tokenString := jwt_str + "." + payload_str + "." + sig
	return tokenString
}

func ParseRSAPrivateKeyFromPEM(key []byte) (*rsa.PrivateKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, err
		}
	}

	var pkey *rsa.PrivateKey
	var ok bool
	if pkey, ok = parsedKey.(*rsa.PrivateKey); !ok {
		return nil, ErrNotRSAPrivateKey
	}

	return pkey, nil
}

//func (tokenInfo TokenCode) RSASign(signingString string, key interface{}) (string, error) {
func RSASign(signingString string, key interface{}) (string, error) {
	var rsaKey *rsa.PrivateKey
	var ok bool

	// Validate type of key
	if rsaKey, ok = key.(*rsa.PrivateKey); !ok {
		return "", ErrInvalidKey
	}

	hasher := sha256.New()
	hasher.Write([]byte(signingString))
	//tokenHash := hasher.Sum(nil)

	// Sign the string and return the encoded bytes
	// signature, err := rsa.SignPSS(rand.Reader, rsaKey, crypto.SHA512, tokenHash, nil)
	if signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hasher.Sum(nil)); err == nil {
		return EncodeSegment(signature), nil
	} else {
		return "", err
	}
}

func EncodeSegment(seg []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(seg), "=")
}

func TestRSAVerify(tokenString string) {
	var key *rsa.PublicKey
	if keyData, err := ioutil.ReadFile(".ssh/id_rsa.pub"); err == nil {
		key, err = ParseRSAPublicKeyFromPEM(keyData)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
	} else {
		fmt.Println(err.Error())
		return
	}

	parts := strings.Split(tokenString, ".")

	err := Verify(strings.Join(parts[0:2], "."), parts[2], key)
	if err != nil {
		fmt.Println(err.Error())
	}
}

func Verify(signingString, signature string, key interface{}) error {
	var err error

	// Decode the signature
	var sig []byte
	if sig, err = DecodeSegment(signature); err != nil {
		return err
	}

	var rsaKey *rsa.PublicKey
	var ok bool

	if rsaKey, ok = key.(*rsa.PublicKey); !ok {
		return ErrInvalidKeyType
	}

	hasher := sha256.New()
	hasher.Write([]byte(signingString))
	tokenHasg := hasher.Sum(nil)

	// Verify the signature
	return rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, tokenHasg, sig)
}

func ParseRSAPublicKeyFromPEM(key []byte) (*rsa.PublicKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, err
		}
	}
	var pkey *rsa.PublicKey
	var ok bool
	if pkey, ok = parsedKey.(*rsa.PublicKey); !ok {
		return nil, ErrNotRSAPublicKey
	}

	return pkey, nil
}

func DecodeSegment(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(seg)
}

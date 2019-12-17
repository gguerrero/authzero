package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"crypto/rsa"

	"github.com/auth0/go-jwt-middleware"
	"github.com/dgrijalva/jwt-go"
)

// Jwks contains the JWT keys
type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

// JSONWebKeys struct representing each JWT key for the app
type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

// CustomClaims struct representing the claims for user permissions contained in a token
type CustomClaims struct {
	Scope string `json:"scope"`
	jwt.StandardClaims
}

const issURI string = "https://gguerrero.auth0.com/"

func New() *jwtmiddleware.JWTMiddleware {
	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: parseTokenToRSAPublicKey,
		SigningMethod: jwt.SigningMethodRS256,
	})

	return jwtMiddleware
}

func CheckScope(scope string, tokenString string) bool {
	token, _ := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func (token *jwt.Token) (interface{}, error) {
		return tokenToRSAPublicKey(token)
	})

	claims, ok := token.Claims.(*CustomClaims)

	hasScope := false
	if ok && token.Valid {
		result := strings.Split(claims.Scope, " ")
		for i := range result {
			if result[i] == scope {
				hasScope = true
			}
		}
	}

	return hasScope
}

func parseTokenToRSAPublicKey(token *jwt.Token) (interface{}, error) {
	// Verify 'aud' claim
	aud := issURI + "api/v2/"
	checkAud := token.Claims.(jwt.MapClaims).VerifyAudience(aud, false)
	if !checkAud {
		return token, errors.New("invalid audience")
	}

	// Verify 'iss' claim
	checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(issURI, false)
	if !checkIss {
		return token, errors.New("invalid issuer")
	}

	return tokenToRSAPublicKey(token)
}

func tokenToRSAPublicKey(token *jwt.Token) (*rsa.PublicKey, error) {
	cert, err := getPemCert(token)
	if err != nil {
		panic(err.Error())
	}

	r, e := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
	return r, e
}

func getPemCert(token *jwt.Token) (string, error) {
	cert := ""
	resp, err := http.Get(issURI + ".well-known/jwks.json")

	if err != nil {
		return cert, err
	}
	defer resp.Body.Close()

	var jwks = Jwks{}
	err = json.NewDecoder(resp.Body).Decode(&jwks)

	if err != nil {
		return cert, err
	}

	for k := range jwks.Keys {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
		}
	}

	if cert == "" {
		err := errors.New("unable to find appropriate key")
		return cert, err
	}

	return cert, nil
}

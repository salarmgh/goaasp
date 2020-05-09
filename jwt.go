package main

import (
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func GetToken(username string) (string, error) {
	now := time.Now()
	claims := UserClaims{
		username,
		jwt.StandardClaims{
			ExpiresAt: now.Unix() + 300,
			Issuer:    "test",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(signingKey)
}

func getParsedClaim(token string) (*jwt.Token, error) {
	parsedToken, err := jwt.ParseWithClaims(token, &UserClaims{},
		func(t *jwt.Token) (interface{}, error) {
			return signingKey, nil
		})
	return parsedToken, err
}

func IsTokenValid(token string) (bool, error) {
	parsedToken, err := getParsedClaim(token)
	if parsedToken.Valid {
		return true, nil
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&(jwt.ValidationErrorExpired|
			jwt.ValidationErrorNotValidYet) != 0 {
			err = errors.New("Token expired")
			return false, err
		} else {
			err = errors.New("Invalid token")
			return false, err
		}
	} else {
		err = errors.New("Invalid token")
		return false, err
	}
}

func GetClaim(token string) (*UserClaims, error) {
	parsedToken, err := getParsedClaim(token)

	valid, err := IsTokenValid(token)
	if valid {
		claims := parsedToken.Claims.(*UserClaims)
		return claims, nil
	} else {
		return nil, err
	}
}

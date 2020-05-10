package main

import (
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type JwtPairs struct {
	access  string
	refresh string
}

func GenTwoPairs(username string) (*JwtPairs, error) {
	accessToken, err := GetToken(username)
	if err != nil {
		return nil, err
	}

	refreshToken, err := GenRefresh()
	if err != nil {
		return nil, err
	}
	pairs := JwtPairs{
		access:  accessToken,
		refresh: refreshToken,
	}
	return &pairs, nil
}

func GetToken(username string) (string, error) {
	claims := UserClaims{
		username,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * accessExpireTime).Unix(),
			Issuer:    issuer,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(signingKey)
}

func GenRefresh() (string, error) {
	refreshToken := jwt.New(jwt.SigningMethodHS256)
	rtClaims := refreshToken.Claims.(jwt.MapClaims)
	rtClaims["exp"] = time.Now().Add(time.Hour * 24 * refreshExpireTime).Unix()
	rt, err := refreshToken.SignedString(signingKey)
	return rt, err
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

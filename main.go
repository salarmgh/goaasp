package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type MyCustomClaims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func main() {
	token, err := getToken("salarmgh")
	if err != nil {
		panic(err)
	}

	claim, err := parseClaims(token)
	if err != nil {
		panic(err)
	}
	fmt.Println(claim.ExpiresAt)
	//ExampleParse_errorChecking(token)
}

func getToken(username string) (string, error) {
	mySigningKey := []byte("AllYourBase")

	now := time.Now()
	claims := MyCustomClaims{
		username,
		jwt.StandardClaims{
			ExpiresAt: now.Unix() + 300,
			Issuer:    "test",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(mySigningKey)
}

func parseClaims(tokenString string) (*MyCustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &MyCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte("AllYourBase"), nil
	})
	if err != nil {
		panic(err)
	}

	if token.Valid {
		claims := token.Claims.(*MyCustomClaims)
		return claims, nil
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			err = errors.New("Token expired")
			return nil, err
		} else {
			err = errors.New("Invalid token")
			return nil, err
		}
	} else {
		err = errors.New("Invalid token")
		return nil, err
	}
}

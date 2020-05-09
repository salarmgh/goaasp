package main

import (
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

	if claims, ok := token.Claims.(*MyCustomClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, err
	}
}

func ExampleParse_errorChecking(tokenString string) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte("AllYourBase"), nil
	})

	fmt.Printf("%v", token.Header)
	if token.Valid {
		fmt.Println("You look nice today")
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			fmt.Println("That's not even a token")
		} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			fmt.Println("Timing is everything")
		} else {
			fmt.Println("Couldn't handle this token:", err)
		}
	} else {
		fmt.Println("Couldn't handle this token:", err)
	}
}

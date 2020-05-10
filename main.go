package main

import (
	"fmt"

	"github.com/dgrijalva/jwt-go"
)

type UserClaims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func main() {
	Initialize()
	pairs, err := GenTwoPairs("salarmgh")
	if err != nil {
		panic(err)
	}

	//claim, err := GetClaim(token)
	//if err != nil {
	//	panic(err)
	//}
	fmt.Println(pairs.access)
	fmt.Println(pairs.refresh)
}

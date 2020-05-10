package main

import "time"

var signingKey []byte
var accessExpireTime time.Duration
var refreshExpireTime time.Duration
var issuer string

func Initialize() {
	signingKey = []byte("AllYourBase")
	accessExpireTime = 15
	refreshExpireTime = 30
}

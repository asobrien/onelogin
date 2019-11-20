package main

import (
	"flag"
)

type config struct {
	// server
	addr string

	// onelogin
	clientID     string
	clientSecret string
	shard        string
	team         string
	appID        string
	mfaDevice    string
}

var cfg = &config{}

func init() {
	flag.StringVar(&cfg.addr, "addr", ":8080", "Address to run proxy server on")

	flag.StringVar(&cfg.clientID, "client-id", "", "OneLogin API client ID")
	flag.StringVar(&cfg.clientSecret, "client-secret", "", "OneLogin API client secret")
	flag.StringVar(&cfg.shard, "shard", "us", "OneLogin API shard location")
	flag.StringVar(&cfg.team, "team", "", "OneLogin team name")
	flag.StringVar(&cfg.appID, "app-id", "", "OneLogin app ID to proxy SAML for")
	flag.StringVar(&cfg.mfaDevice, "mfa-device", "Google Authenticator",
		"OneLogin MFA device to authenticate against")
}

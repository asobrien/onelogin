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
}

var cfg = &config{}

func init() {
	flag.StringVar(&cfg.addr, "addr", ":8080", "Address to run proxy server on")

	flag.StringVar(&cfg.clientID, "client_id", "", "OneLogin API client ID")
	flag.StringVar(&cfg.clientSecret, "client_secret", "", "OneLogin API client secret")
	flag.StringVar(&cfg.shard, "shard", "us", "OneLogin API shard location")
	flag.StringVar(&cfg.team, "team", "", "OneLogin team name")
	flag.StringVar(&cfg.appID, "app_id", "", "OneLogin app ID to proxy SAML for")
}

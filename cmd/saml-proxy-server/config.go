package main

import (
	"flag"
	"fmt"
	"strings"
)

type config struct {
	// server
	addr     string
	certFile string
	keyFile  string

	// onelogin
	clientID     string
	clientSecret string
	shard        string
	team         string
	mfaDevice    string
	appID        []string
}

type sliceFlags []string

func (s sliceFlags) String() string {
	return fmt.Sprintf(strings.Join(s, ","))
}

func (s *sliceFlags) Set(val string) error {
	*s = append(*s, val)
	return nil
}

var cfg = &config{}

func init() {
	flag.StringVar(&cfg.addr, "addr", ":8443", "Address to run proxy server on")
	flag.StringVar(&cfg.certFile, "cert-file", "/var/onelogin/cert.pem", "Path to TLS certificate file")
	flag.StringVar(&cfg.keyFile, "key-file", "/var/onelogin/key.pem", "Path to TLS private key file")

	flag.StringVar(&cfg.clientID, "client-id", "", "OneLogin API client ID")
	flag.StringVar(&cfg.clientSecret, "client-secret", "", "OneLogin API client secret")
	flag.StringVar(&cfg.shard, "shard", "us", "OneLogin API shard location")
	flag.StringVar(&cfg.team, "team", "", "OneLogin team name")
	flag.StringVar(&cfg.mfaDevice, "mfa-device", "Google Authenticator",
		"OneLogin MFA device to authenticate against")

	var appIDFlags sliceFlags
	flag.Var(&appIDFlags, "app-id", "Restrict SAML to specified app ID, may be repeated")

	flag.Parse()
	cfg.appID = appIDFlags
}

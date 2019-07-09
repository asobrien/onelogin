// saml-proxy-server provides a server that can be used to proxy SAML assertion
// requests from a trusted server.
//
// This server can be used directly, however it is *highly* advised to bind
// this program to an appropriate frontend server or load-balancer that can
// handle TLS termination. Without doing this you'll allow passwords to fly
// around the network in plaintext and you violate the trust of your users.
package main

import (
	"errors"
	"flag"
	"log"
	"net/http"

	"github.com/asobrien/onelogin"
)

type server struct {
	router   *http.ServeMux
	onelogin *onelogin.Client
}

func newOneloginClient() (*onelogin.Client, error) {
	if cfg.clientID == "" {
		return nil, errors.New("config error: clientID is unset")
	} else if cfg.clientSecret == "" {
		return nil, errors.New("config error: clientSecret is unset")
	} else if cfg.team == "" {
		return nil, errors.New("config error: team is unset")
	}

	return onelogin.New(cfg.clientID, cfg.clientSecret, cfg.shard, cfg.team), nil
}

func main() {
	flag.Parse()

	oneloginClient, err := newOneloginClient()
	if err != nil {
		log.Fatal(err)
	}

	srv := server{
		router:   http.NewServeMux(),
		onelogin: oneloginClient,
	}
	srv.routes()

	if err := http.ListenAndServe(cfg.addr, srv.router); err != nil {
		log.Fatal(err)
	}
}

// +build uat

package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/asobrien/onelogin"
	pwd "github.com/hashicorp/vault/sdk/helper/password"
)

type config struct {
	// onelogin API auth client
	clientID     string
	clientSecret string
	shard        string
	team         string
}

var cfg = &config{}

func init() {
	flag.StringVar(&cfg.clientID, "client_id", "", "OneLogin API client ID")
	flag.StringVar(&cfg.clientSecret, "client_secret", "", "OneLogin API client secret")
	flag.StringVar(&cfg.shard, "shard", "us", "OneLogin API shard location")
	flag.StringVar(&cfg.team, "team", "", "OneLogin team name")
}

func TestUATLoginService_AuthenticateWithPushVerify() {
	c := onelogin.New(cfg.clientID, cfg.clientSecret, cfg.shard, cfg.team)

	// prompt for credentials
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Username: ")
	username, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("unexpected error: %v\n", err)
		os.Exit(1)
	}
	username = strings.TrimSuffix(username, "\n")

	fmt.Print("Password (will be hidden): ")
	password, err := pwd.Read(os.Stdin)
	fmt.Println()
	if err != nil {
		fmt.Printf("unexpected error: %v\n", err)
		os.Exit(1)
	}

	// Authenticate and generate a SMS token
	resp, err := c.Login.AuthenticateWithPushVerify(context.Background(), username, password, "OneLogin SMS")

	if err != nil {
		fmt.Printf("authentication error: %v\n", err)
		os.Exit(1)
	}

	// prompt for token
	reader = bufio.NewReader(os.Stdin)
	fmt.Print("MFA Token: ")
	token, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("unexpected error: %v\n", err)
		os.Exit(1)
	}
	token = strings.TrimSuffix(token, "\n")

	// verify token and conmplete authentication
	_, err = c.Login.VerifyPushToken(context.Background(), resp, token)
	if err != nil {
		fmt.Printf("authentication error: %v\n", err)
		os.Exit(1)
	}
}

func main() {
	flag.Parse()
	TestUATLoginService_AuthenticateWithPushVerify()
}

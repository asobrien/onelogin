// +build integration

package onelogin_test

import (
	"context"
	"errors"
	"flag"
	"testing"
	"time"

	"github.com/asobrien/onelogin"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type config struct {
	// onelogin API auth client
	clientID     string
	clientSecret string
	shard        string
	team         string

	// onelogin user
	username string
	password string
	otpURL   string

	// saml
	appID string
}

var cfg = &config{}

func init() {
	flag.StringVar(&cfg.clientID, "client-id", "", "OneLogin API client ID")
	flag.StringVar(&cfg.clientSecret, "client-secret", "", "OneLogin API client secret")
	flag.StringVar(&cfg.shard, "shard", "us", "OneLogin API shard location")
	flag.StringVar(&cfg.team, "team", "", "OneLogin team name")

	flag.StringVar(&cfg.username, "username", "", "OneLogin username")
	flag.StringVar(&cfg.password, "password", "", "OneLogin password")
	flag.StringVar(&cfg.otpURL, "otp-url", "", "OneLogin OTP URL, used to generate TOTP as needed")

	flag.StringVar(&cfg.appID, "app-id", "", "OneLogin app ID to test SAML with")
}

// Generate a TOTP token from a OTP URL.
// See: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
func generateTOTPToken(url string) (string, error) {
	if url == "" {
		return "", errors.New("OTP URL is empty")
	}

	key, err := otp.NewKeyFromURL(url)
	if err != nil {
		return "", err
	}

	return totp.GenerateCode(key.Secret(), time.Now().UTC())
}

func TestLoginAuthenticate(t *testing.T) {
	c := onelogin.New(cfg.clientID, cfg.clientSecret, cfg.shard, cfg.team)

	var tests = []struct {
		name     string
		username string
		password string
		want     string
		wantErr  bool
	}{
		{
			"valid user",
			cfg.username,
			cfg.password,
			cfg.username,
			false,
		},
		{
			"non-existent user",
			"user-does-not-exist",
			"no-password-for-no-user",
			"",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := c.Login.Authenticate(context.Background(), tt.username, tt.password)
			if !tt.wantErr && (err != nil) {
				t.Errorf("no error expected, got: %v", err)
			}
			if tt.wantErr && (err == nil) {
				t.Error("expected error, got nil")
			}

			var got string
			// ensure the user expected is returned in auth response
			if user != nil {
				got = user.Email
			}
			if got != tt.want {
				t.Errorf("got: %v, want: %v", got, tt.want)
			}
		})
	}
}

func TestLoginAuthenticateWithVerify(t *testing.T) {
	c := onelogin.New(cfg.clientID, cfg.clientSecret, cfg.shard, cfg.team)

	var tests = []struct {
		name     string
		username string
		password string
		device   string
		token    string
		want     string
		wantErr  bool
	}{
		{
			"valid user with valid device",
			cfg.username,
			cfg.password,
			"Google Authenticator",
			"",
			cfg.username,
			false,
		},
		{
			"valid user with unregistered device",
			cfg.username,
			cfg.password,
			"unregistered MFA device",
			"123456",
			"",
			true,
		},
		{
			"valid user with invalid token",
			cfg.username,
			cfg.password,
			"Google Authenticator",
			"1234567890",
			"",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error

			// generate token if none is passed
			token := tt.token
			if token == "" {
				token, err = generateTOTPToken(cfg.otpURL)
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}

			var got string
			user, err := c.Login.AuthenticateWithVerify(context.Background(), tt.username, tt.password, tt.device, token)
			if !tt.wantErr && (err != nil) {
				t.Errorf("no error expected, got: %v", err)
			}
			if tt.wantErr && (err == nil) {
				t.Error("expected error, got nil")
			}

			// ensure the user expected is returned in auth response
			if user != nil {
				got = user.Email
			}
			if got != tt.want {
				t.Errorf("got: %v, want: %v", got, tt.want)
			}
		})
	}
}

func TestLoginAuthenticateWithPushVerify(t *testing.T) {
	c := onelogin.New(cfg.clientID, cfg.clientSecret, cfg.shard, cfg.team)

	var tests = []struct {
		name     string
		username string
		password string
		device   string
		want     string
		wantErr  bool
	}{
		{
			"valid user with valid push device",
			cfg.username,
			cfg.password,
			"OneLogin SMS",
			"",
			false,
		},
		{
			"valid user with invalid push device",
			cfg.username,
			cfg.password,
			"Google Authenticator",
			"POST https://api.us.onelogin.com/api/1/login/verify_factor: OneLogin responsed with code 400, type bad request and message OTP token blank",
			true,
		},
		{
			"valid user with unregistered device",
			cfg.username,
			cfg.password,
			"unregistered MFA device",
			"verify device not found: unregistered MFA device",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got string
			_, err := c.Login.AuthenticateWithPushVerify(context.Background(), tt.username, tt.password, tt.device)
			if !tt.wantErr && (err != nil) {
				t.Errorf("no error expected, got: %v", err)
			}
			if tt.wantErr && (err == nil) {
				t.Error("expected error, got nil")
			}

			if tt.wantErr {
				got = err.Error()
			}
			if got != tt.want {
				t.Errorf("got: %v, want: %v", got, tt.want)
			}
		})
	}
}

func TestLoginVerifyPushToken(t *testing.T) {
	c := onelogin.New(cfg.clientID, cfg.clientSecret, cfg.shard, cfg.team)

	var tests = []struct {
		name     string
		username string
		password string
		device   string
		token    string
		want     string
		wantErr  bool
	}{
		{
			"valid user with invalid push code",
			cfg.username,
			cfg.password,
			"OneLogin SMS",
			"1234567890",
			"POST https://api.us.onelogin.com/api/1/login/verify_factor: OneLogin responsed with code 401, type Unauthorized and message Failed authentication with this factor",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got string
			a, err := c.Login.AuthenticateWithPushVerify(context.Background(), tt.username, tt.password, tt.device)
			if err != nil {
				t.Fatalf("unexpected AuthenticateWithPushVerify error: %v", err)
			}

			_, err = c.Login.VerifyPushToken(context.Background(), a, tt.token)
			if !tt.wantErr && (err != nil) {
				t.Errorf("no error expected, got: %v", err)
			}
			if tt.wantErr && (err == nil) {
				t.Error("expected error, got nil")
			}

			if tt.wantErr {
				got = err.Error()
			}
			if got != tt.want {
				t.Errorf("got: %v, want: %v", got, tt.want)
			}
		})
	}
}

func TestGenerateSAMLAssertion(t *testing.T) {
	c := onelogin.New(cfg.clientID, cfg.clientSecret, cfg.shard, cfg.team)

	var tests = []struct {
		name     string
		username string
		password string
		appID    string
		want     string
		wantErr  bool
	}{
		{
			"valid user with valid app",
			cfg.username,
			cfg.password,
			cfg.appID,
			"",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := c.SAMLService.GenerateSAMLAssertion(context.Background(), tt.username, tt.password, tt.appID, "")
			if err != nil {
				t.Fatalf("error generating SAML assertion: %v", err)
			}
		})
	}
}

package onelogin

import (
	"context"
	"errors"
)

// LoginService handles communications with login pages.
// https://developers.onelogin.com/api-docs/1/login-page/login-user-via-api
type LoginService struct {
	auth         *authResponse
	verifyDevice *string
	*service
}

// authParams is a struct that holds information required as part of requests that
// are used to authenticate a user.
type authParams struct {
	Username  string `json:"username_or_email"`
	Password  string `json:"password"`
	Subdomain string `json:"subdomain"`
}

// authResponse is a struct where data in the authentication response can be
// marshalled into.
type authResponse struct {
	Status       string             `json:"status"`
	User         *AuthenticatedUser `json:"user"`
	ReturnToURL  string             `json:"return_to_url"`
	ExpiresAt    string             `json:"expires_at"`
	SessionToken string             `json:"session_token"`
	StateToken   string             `json:"state_token"`
	CallbackUrl  string             `json:"callback_url"`
	Devices      []*Devices         `json:"devices"`
}

// AuthenticatedUser contains user information for the Authentication.
type AuthenticatedUser struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
}

// authenticate a user via the API. This function returns an *authResponse, which can be used to
// setup downstream verification with a second-factor device. The public method to authenticate a
// user is 'Authenticate' which returns user details upon successful authentication.
func (s *LoginService) authenticate(ctx context.Context, emailOrUsername string, password string) (*authResponse, error) {
	u := "/api/1/login/auth"

	a := authParams{
		Username:  emailOrUsername,
		Password:  password,
		Subdomain: s.client.subdomain,
	}

	req, err := s.client.NewRequest("POST", u, a)
	if err != nil {
		return nil, err
	}

	if err := s.client.AddAuthorization(ctx, req); err != nil {
		return nil, err
	}

	var d []authResponse
	_, err = s.client.Do(ctx, req, &d)
	if err != nil {
		return nil, err
	}

	// auth is successful even if additional verification is required and a
	// state_token is issued.
	// https://developers.onelogin.com/api-docs/1/login-page/create-session-login-token
	if len(d) == 1 && (d[0].Status == "Authenticated" || d[0].StateToken != "") {
		s.auth = &d[0]
		return &d[0], nil
	}
	return nil, errors.New("authentication failed")
}

// Authenticate a user with an email (or username) and a password. Note that a user can *always* successfully
// authenticate whether or not MFA is required. To check whether a user is able to verify with strict MFA compliance,
// AuthenticateWithVerify should be used.
func (s *LoginService) Authenticate(ctx context.Context, emailOrUsername string, password string) (*AuthenticatedUser, error) {
	auth, err := s.authenticate(ctx, emailOrUsername, password)
	if err != nil {
		return nil, err
	}
	return auth.User, nil
}

// AuthenticateWithVerify is used to strictly verify that a user is able both: authenticate with username and password AND to verify
// a user's second-factor device. If both conditions are not satisfied an error will be returned.
func (s *LoginService) AuthenticateWithVerify(ctx context.Context, emailOrUsername string, password string, device string, token string) (*AuthenticatedUser, error) {
	u := "/api/1/login/verify_factor"

	// authenticate to verify username and password and generate auth response
	auth, err := s.authenticate(ctx, emailOrUsername, password)
	if err != nil {
		return nil, err
	}

	d, err := getDeviceID(device, s.auth.Devices)
	if err != nil {
		return nil, err
	}

	// regenerate authenticateResponse via the verify_factor endpoint
	p := &verifyFactorParams{
		DeviceID:    d,
		StateToken:  auth.StateToken,
		OTPToken:    token,
		DoNotNotify: true,
	}
	_, err = s.client.verifyFactor(ctx, u, p)
	if err != nil {
		return nil, err
	}

	return auth.User, nil
}

// AuthenticateWithPushVerify can be used with asynchronous factor methods (e.g., SMS). This function is first called to
// verify username/password authentication and then to generate a push event. Note that this function does not return
// user information if authentication is successful, a follow call via VerifyPushToken is required to verify the passcode
// generated in the push event and complete authentication.
func (s *LoginService) AuthenticateWithPushVerify(ctx context.Context, emailOrUsername string, password string, device string) error {
	u := "/api/1/login/verify_factor"

	auth, err := s.authenticate(ctx, emailOrUsername, password)
	if err != nil {
		return err
	}

	d, err := getDeviceID(device, auth.Devices)
	if err != nil {
		return err
	}

	// generate a push code, pass empty token as push notify generates token
	p := &verifyFactorParams{
		DeviceID:    d,
		StateToken:  auth.StateToken,
		DoNotNotify: false,
	}
	_, err = s.client.verifyFactor(ctx, u, p)
	return err
}

// VerifyPushToken is a follow-on to AuthenticateWithPushVerify and it used to complete second-factor authentication
// of an asynchronous device. If this is called prior to the generation of a token via AuthenticateWithPushVerify,
// an error will be returned.
func (s *LoginService) VerifyPushToken(ctx context.Context, token string) (*AuthenticatedUser, error) {
	u := "/api/1/login/verify_factor"

	if s.verifyDevice == nil {
		return nil, errors.New("no verifyDevice assigned, 'AuthenticateWithPush' needs to called before this function can be used")
	}

	// do not push notify on verify
	p := &verifyFactorParams{
		DeviceID:    *s.verifyDevice,
		StateToken:  s.auth.StateToken,
		OTPToken:    token,
		DoNotNotify: true,
	}
	_, err := s.client.verifyFactor(ctx, u, p)
	if err != nil {
		return nil, err
	}

	return s.auth.User, nil
}

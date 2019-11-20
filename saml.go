package onelogin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// SAMLService deals with OneLogin SAML assertions.
type SAMLService struct {
	*service
}

type samlResponse struct {
}

// samlParams is a struct that holds the parameters required when making a
// SAML assertion request. This is used as the POST body.
type samlParams struct {
	Username  string `json:"username_or_email"`
	Password  string `json:"password"`
	AppID     string `json:"app_id"`
	Subdomain string `json:"subdomain"`
	IPAddress string `json:"ip_address,omitempty"`
}

// SAMLResponseMFA is a struct that contains details about MFA verification.
type SAMLResponseMFA struct {
	StateToken  string             `json:"state_token"`
	Devices     []*Device          `json:"devices"`
	CallbackURL string             `json:"callback_url"`
	User        *AuthenticatedUser `json:"user"`
}

// SAMLAssertion is a struct that contains the SAML assertion response, it
// contains both the Assertion and the MFAResponse. Note that only one of
// these fields won't be nil, depending on the response from the endpoing.
// If MFA is required, this won't contain the Assertion but will contain the
// an initialized SAMLResponseMFA struct which contains additional information
// required to proceed.
type SAMLAssertion struct {
	Status    string
	Message   string
	Assertion *string
	MFA       *SAMLResponseMFA
}

// GenerateSAMLAssertion returns the SAML assertion if MFA is not required, in
// the case that MFA is required that info is part of the response.
func (s *SAMLService) GenerateSAMLAssertion(ctx context.Context, emailOrUsername, password, appID, ipAddress string) (*SAMLAssertion, error) {
	u := "/api/1/saml_assertion"

	p := samlParams{
		Username:  emailOrUsername,
		Password:  password,
		AppID:     appID,
		Subdomain: s.client.subdomain,
		IPAddress: ipAddress,
	}

	req, err := s.client.NewRequest("POST", u, p)
	if err != nil {
		return nil, err
	}

	if err := s.client.AddAuthorization(ctx, req); err != nil {
		return nil, err
	}

	var b bytes.Buffer
	resp, err := s.client.Do(ctx, req, &b)
	if err != nil {
		return nil, err
	}

	// Check that the request was a 'success',  additional verfication
	// will be required if MFA is requisite but the response is still
	// considered a 'success'.
	// https://developers.onelogin.com/api-docs/1/saml-assertions/generate-saml-assertion
	if err = CheckResponse(resp.Response); err != nil {
		return nil, err
	}

	// Read the response to determine if this 'success' event requires MFA in
	// order to proceed with obtaining the SAML assertion.
	var m responseMessage
	err = json.Unmarshal(b.Bytes(), &m)
	if err != nil {
		return nil, err
	}

	if m.Status.Error {
		return nil, fmt.Errorf("unexpected error generating SAML assertion: %s", m.Status.Message)
	}
	assertion := &SAMLAssertion{
		Status:  m.Status.Type,
		Message: m.Status.Message,
	}

	// Nothing to unpack, bail out
	if assertion.Status == "pending" {
		return assertion, nil
	}

	err = nil
	switch assertion.Message {
	case "Success":
		r := ""
		err = json.Unmarshal(m.Data, &r)
		assertion.Assertion = &r
	case "MFA is required for this user":
		var r []SAMLResponseMFA
		err = json.Unmarshal(m.Data, &r)
		if len(r) != 1 {
			err = errors.New("unexpected number of elements in MFA response")
		} else {
			assertion.MFA = &r[0]
		}
	default:
		err = fmt.Errorf("unable to parse response message: %s", assertion.Message)
	}

	return assertion, err
}

// GenerateSAMLAssertionWithVerify returns a SAML assertion forcing the use of
// synchronous MFA at the time this function is called. This can be used with
// with synchronous methods like 'Google Authenticator'.
func (s *SAMLService) GenerateSAMLAssertionWithVerify(ctx context.Context, emailOrUsername, password, appID, ipAddress string, device string, token string) (*SAMLAssertion, error) {
	saml, err := s.GenerateSAMLAssertion(ctx, emailOrUsername, password, appID, ipAddress)
	if err != nil {
		return nil, err
	}

	if saml.MFA == nil {
		return nil, errors.New("no MFA details in response")
	}

	deviceID, err := getDeviceID(device, saml.MFA.Devices)
	if err != nil {
		return nil, err
	}

	p := &verifyFactorParams{
		AppID:       appID,
		DeviceID:    deviceID,
		StateToken:  saml.MFA.StateToken,
		OTPToken:    token,
		DoNotNotify: true,
	}

	resp, err := s.client.verifyFactor(ctx, saml.MFA.CallbackURL, p)
	if err != nil {
		return nil, err
	}

	// unpack assertion
	var r string
	err = json.Unmarshal(resp.Data, &r)
	if err != nil {
		return saml, err
	}
	saml.Assertion = &r

	return saml, nil
}

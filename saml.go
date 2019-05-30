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
	StateToken  string             `json:"state_token`
	Devices     []*Devices         `json:"devices"`
	CallbackUrl string             `json:"callback_url"`
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

	// Verify that the response is successful
	if m.Status.Error {
		return nil, errors.New(fmt.Sprintf("unexpected error generating SAML assertion: %s", m.Status.Message))
	}

	// Unpack based on message
	assertion := &SAMLAssertion{
		Status:  m.Status.Type,
		Message: m.Status.Message,
	}

	// Nothing to unpack, just get out of here
	if assertion.Status == "pending" {
		return assertion, nil
	}

	err = nil
	switch assertion.Message {
	case "Success":
		// unpack data into assertion
		s := ""
		err = json.Unmarshal(m.Data, &s)
		assertion.Assertion = &s
	case "MFA is required for this user":
		// unpack into MFA
		var s []SAMLResponseMFA
		err = json.Unmarshal(m.Data, &s)
		assertion.MFA = &s[0] // TODO: check bounds
	default:
		// some sort of error
		err = errors.New(fmt.Sprintf("unable to parse response message: %s", assertion.Message))
	}

	return assertion, err
}

package onelogin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// verifyFactorParams is a struct that holds information requeired in requests that
// verify a user's second-factor device.
type verifyFactorParams struct {
	AppID       string `json:"app_id,omitempty"`
	DeviceID    string `json:"device_id"`
	StateToken  string `json:"state_token,omitempty"`
	OTPToken    string `json:"otp_token"`
	DoNotNotify bool   `json:"do_not_notify"`
}

// Devices contains registered user devices that can be used for MFA.
type Device struct {
	DeviceType string `json:"device_type"`
	DeviceID   int64  `json:"device_id"`
}

// Get the user's deviceID or error
func getDeviceID(name string, devices []*Device) (string, error) {
	var deviceID string

	for _, d := range devices {
		if d.DeviceType == name {
			deviceID = strconv.FormatInt(d.DeviceID, 10)
			break
		}
	}

	if deviceID == "" {
		return "", errors.New(fmt.Sprintf("verify device not found: %s", name))
	}

	return deviceID, nil
}

// verifyFactor handles calls the `verify_factor` endpoint. This function can be used to either directly
// verify the passcode from a factor device, or to generate a push to a device (e.g., SMS). Note that
// this function does not verify appropriate behavior, that is delegated to the API. For example, a
// 'Google Authenticator' device can not generate a push event.
// https://developers.onelogin.com/api-docs/1/login-page/verify-factor
func (s *Client) verifyFactor(ctx context.Context, endpoint string, p *verifyFactorParams) (*responseMessage, error) {
	req, err := s.NewRequest("POST", endpoint, p)
	if err != nil {
		return nil, err
	}

	if err := s.AddAuthorization(ctx, req); err != nil {
		return nil, err
	}

	var b bytes.Buffer
	_, err = s.Do(ctx, req, &b)
	if err != nil {
		return nil, err
	}

	var m responseMessage
	err = json.Unmarshal(b.Bytes(), &m)
	if err != nil {
		return nil, err
	}

	// Read the associate response data upon successful verification. This is either a
	// push event follow-up call or a verification of device with a known passcode.
	if m.Status.Error {
		err = errors.New("verify factor failed")
	}

	return &m, err
}

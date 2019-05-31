package onelogin

import (
    "context"
    "errors"
    "strconv"
    "fmt"
    "bytes"
    "encoding/json"
)

// TODO: move to device.go
// verifyFactorParams is a struct that holds information requeired in requests that
// verify a user's second-factor device.
type verifyFactorParams struct {
    AppID       string `json:"app_id,omitempty"`
	DeviceID    string `json:"device_id"`
	StateToken  string `json:"state_token"`
	OTPToken    string `json:"otp_token"`
	DoNotNotify bool   `json:"do_not_notify"`
}


// Devices contains registered user devices that can be used for MFA.
type Devices struct {
	DeviceType string `json:"device_type"`
	DeviceID   int64  `json:"device_id"`
}

// TODO: move to device.go
// Get the user's deviceID or error
func getDeviceID(name string, devices []*Devices) (string, error) {
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
func (s *Client) verifyFactorClone(ctx context.Context, endpoint string, p *verifyFactorParams) (*responseMessage, error) {

    // NOTE: only applicable for LoginService
	// u := "/api/1/login/verify_factor"


	// Get the user's deviceID or error
	// var deviceID string
	// for _, d := range s.auth.Devices {
	// 	if d.DeviceType == device {
	// 		deviceID = strconv.FormatInt(d.DeviceID, 10)
	// 		break
	// 	}
	// }
	// if deviceID == "" {
	// 	return nil, errors.New(fmt.Sprintf("verify device not found: %s", device))
	// }

    // FIXME: move to caller
    // deviceID, err := getDeviceID(device, s.auth.Devices)
    // if err != nil {
    //     return nil, err
    // }

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

	// Read the raw response to determine if this is a 'pending' or a 'success' event.
	// Push verification generates 'pending' events, while devices with known passcodes will
	// generate 'success' events.
	var m responseMessage
	err = json.Unmarshal(b.Bytes(), &m)
	if err != nil {
		return nil, err
	}

    // FIXME: this belongs in auth
	// If this is push verification, there is no response data
	// if m.Status.Code == 200 && m.Status.Type == "pending" {
	// 	return nil, nil
	// }

	// Read the associate response data upon successful verification. This is either a
	// push event follow-up call or a verification of device with a known passcode.
	if m.Status.Error {
	    err = errors.New("verify factor failed")
	}

    return &m, err
}

// verifyFactor handles calls the `verify_factor` endpoint. This function can be used to either directly
// verify the passcode from a factor device, or to generate a push to a device (e.g., SMS). Note that
// this function does not verify appropriate behavior, that is delegated to the API. For example, a
// 'Google Authenticator' device can not generate a push event.
// https://developers.onelogin.com/api-docs/1/login-page/verify-factor
//
// TODO: clone, modify to use verifyFactorParams and test with SAML
//       then fix in corresponding login.go
func (s *LoginService) verifyFactor(ctx context.Context, endpoint, device, token string, doNotVerify bool) (*authResponse, error) {

    // NOTE: only applicable for LoginService
	// u := "/api/1/login/verify_factor"

	if s.auth == nil {
		return nil, errors.New("auth is nil, successful prior authentication required")
	}

	// Get the user's deviceID or error
	// var deviceID string
	// for _, d := range s.auth.Devices {
	// 	if d.DeviceType == device {
	// 		deviceID = strconv.FormatInt(d.DeviceID, 10)
	// 		break
	// 	}
	// }
	// if deviceID == "" {
	// 	return nil, errors.New(fmt.Sprintf("verify device not found: %s", device))
	// }

    deviceID, err := getDeviceID(device, s.auth.Devices)
    if err != nil {
        return nil, err
    }

	s.verifyDevice = &device
	a := verifyFactorParams{
		DeviceID:    deviceID,
		StateToken:  s.auth.StateToken,
		OTPToken:    token,
		DoNotNotify: doNotVerify,
	}

	req, err := s.client.NewRequest("POST", endpoint, a)
	if err != nil {
		return nil, err
	}

	if err := s.client.AddAuthorization(ctx, req); err != nil {
		return nil, err
	}

	var b bytes.Buffer
	_, err = s.client.Do(ctx, req, &b)
	if err != nil {
		return nil, err
	}

	// Read the raw response to determine if this is a 'pending' or a 'success' event.
	// Push verification generates 'pending' events, while devices with known passcodes will
	// generate 'success' events.
	var m responseMessage
	err = json.Unmarshal(b.Bytes(), &m)
	if err != nil {
		return nil, err
	}

	// If this is push verification, there is no response data
	if m.Status.Code == 200 && m.Status.Type == "pending" {
		return nil, nil
	}

	// Read the associate response data upon successful verification. This is either a
	// push event follow-up call or a verification of device with a known passcode.
	if m.Status.Code == 200 && m.Status.Type == "success" {
		var d []authResponse
		err = json.Unmarshal(m.Data, &d)
		if err != nil {
			return nil, err
		}
		if len(d) == 1 && d[0].Status == "Authenticated" {
			return &d[0], nil
		}
	}

	return nil, errors.New("verify factor failed")
}
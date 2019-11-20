package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

func (s *server) handleIndex() http.HandlerFunc {
	return http.NotFound
}

func (s *server) samlPost(req *http.Request) ([]byte, error) {
	var data []byte

	d := json.NewDecoder(req.Body)
	d.DisallowUnknownFields() // strict content

	t := struct {
		Username *string `json:"username"`
		Password *string `json:"password"`
		MFAToken *string `json:"mfa_token"`
	}{}

	err := d.Decode(&t)
	if err != nil {
		return data, err
	}
	if t.Username == nil {
		return data, errors.New("required field is missing: 'username'")
	} else if t.Password == nil {
		return data, errors.New("required field is missing: 'password'")
	} else if t.MFAToken == nil {
		return data, errors.New("required field is missing: 'mfa-token'")
	}

	saml, err :=
		s.onelogin.SAMLService.GenerateSAMLAssertionWithVerify(context.Background(),
			*t.Username, *t.Password, cfg.appID, "", cfg.mfaDevice, *t.MFAToken)
	if err != nil {
		return data, err
	}
	if saml.Assertion == nil {
		return data, errors.New("empty SAML assertion")
	}

	r := struct {
		Data string `json:"data"`
	}{}
	r.Data = *saml.Assertion
	data, err = json.Marshal(r)
	return data, err
}

func (s *server) handleSAML() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case http.MethodPost:
			// do it
			json, err := s.samlPost(req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(json)
		default:
			http.Error(w, "405 method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

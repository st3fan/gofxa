// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

package fxa

import (
	"bytes"
	"crypto/dsa"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

type Client struct {
	email         string
	password      string
	authPW        []byte
	unwrapBKey    []byte
	uid           string // After /account/login
	sessionToken  []byte
	keyFetchToken []byte
	KeyA          []byte // After /account/keys
	KeyB          []byte
}

type LoginRequest struct {
	Email  string `json:"email"`
	AuthPW string `json:"authPW"`
}

type LoginResponse struct {
	Uid           string `json:"uid"`
	SessionToken  string `json:"sessionToken"`
	KeyFetchToken string `json:"keyFetchToken"`
}

type KeysResponse struct {
	Bundle string `json:"bundle"`
}

type DSAPublicKey struct {
	Algorithm string `json:"algorithm"`
	Y         string `json:"y"`
	P         string `json:"p"`
	Q         string `json:"q"`
	G         string `json:"g"`
}

type SignCertificateRequest struct {
	PublicKey DSAPublicKey `json:"publicKey"`
	Duration  uint64       `json:"duration"`
}

func NewClient(email, password string) (*Client, error) {
	authPW, err := deriveAuthPWFromQuickStretchedPassword(quickStretchPassword(email, password))
	if err != nil {
		return nil, err
	}

	unwrapBKey, err := deriveUnwrapBKeyFromQuickStretchedPassword(quickStretchPassword(email, password))
	if err != nil {
		return nil, err
	}

	return &Client{
		email:      email,
		password:   password,
		authPW:     authPW,
		unwrapBKey: unwrapBKey,
	}, nil
}

func (c *Client) Login() error {
	loginRequest := LoginRequest{
		Email:  c.email,
		AuthPW: hex.EncodeToString(c.authPW),
	}
	encodedLoginRequest, err := json.Marshal(loginRequest)
	if err != nil {
		return err
	}

	u, err := url.Parse("https://api.accounts.firefox.com/v1/account/login?keys=true")
	if err != nil {
		return err
	}

	res, err := http.Post(u.String(), "application/json", bytes.NewBuffer(encodedLoginRequest))
	if err != nil {
		return err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	if res.StatusCode != http.StatusOK {
		return errors.New(res.Status) // TODO: Proper errors based on what the server returns
	}

	loginResponse := &LoginResponse{}
	if err = json.Unmarshal(body, loginResponse); err != nil {
		return err
	}

	c.uid = loginResponse.Uid
	c.sessionToken, _ = hex.DecodeString(loginResponse.SessionToken)
	c.keyFetchToken, _ = hex.DecodeString(loginResponse.KeyFetchToken)

	return nil
}

func (c *Client) FetchKeys() error {
	u, err := url.Parse("https://api.accounts.firefox.com/v1/account/keys")
	if err != nil {
		return err
	}

	client := &http.Client{}

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return err
	}

	requestCredentials, err := NewRequestCredentials(c.keyFetchToken, "keyFetchToken")
	if err != nil {
		return err
	}

	hawkCredentials := NewHawkCredentials(hex.EncodeToString(requestCredentials.TokenId), requestCredentials.RequestHMACKey)
	if err := hawkCredentials.AuthorizeRequest(req, nil, ""); err != nil {
		return err
	}

	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	if res.StatusCode != http.StatusOK {
		return errors.New(res.Status) // TODO: Proper errors based on what the server returns
	}

	keysResponse := &KeysResponse{}
	if err = json.Unmarshal(body, keysResponse); err != nil {
		return err
	}

	accountKeys, err := NewAccountKeys(requestCredentials.RequestKey)
	if err != nil {
		return err
	}

	//

	bundle, err := hex.DecodeString(keysResponse.Bundle)
	if err != nil {
		return err
	}

	ct := bundle[0:64]
	respMAC := bundle[64:96]

	mac := hmac.New(sha256.New, accountKeys.HMACKey)
	mac.Write(ct)
	respMAC2 := mac.Sum(nil)

	if !bytes.Equal(respMAC, respMAC2) {
		return errors.New("Response MAC failure something bad")
	}

	// Finally derive kA and kB

	var t1 [64]byte
	for i := 0; i < 64; i++ {
		t1[i] = ct[i] ^ accountKeys.XORKey[i]
	}

	c.KeyA = t1[0:32]

	var t2 [32]byte
	for i := 0; i < len(t2); i++ {
		t2[i] = c.unwrapBKey[i] ^ t1[32+i]
	}
	c.KeyB = t2[:]

	return nil
}

func (c *Client) SignCertificate(key *dsa.PrivateKey) (string, error) {
	u, err := url.Parse("https://api.accounts.firefox.com/v1/certificate/sign")
	if err != nil {
		return "", err
	}

	signRequest := SignCertificateRequest{
		PublicKey: DSAPublicKey{
			Algorithm: "DS",
			Y:         fmt.Sprintf("%x", key.PublicKey.Y),
			P:         fmt.Sprintf("%x", key.PublicKey.Parameters.P),
			Q:         fmt.Sprintf("%x", key.PublicKey.Parameters.Q),
			G:         fmt.Sprintf("%x", key.PublicKey.Parameters.G),
		},
		Duration: 86400000,
	}
	encodedSignRequest, err := json.Marshal(signRequest)
	if err != nil {
		return "", err
	}

	client := &http.Client{}

	req, err := http.NewRequest("POST", u.String(), bytes.NewReader(encodedSignRequest))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	requestCredentials, err := NewRequestCredentials(c.sessionToken, "sessionToken")
	if err != nil {
		return "", err
	}

	hawkCredentials := NewHawkCredentials(hex.EncodeToString(requestCredentials.TokenId), requestCredentials.RequestHMACKey)
	if err := hawkCredentials.AuthorizeRequest(req, bytes.NewReader(encodedSignRequest), ""); err != nil {
		return "", err
	}

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	if res.StatusCode != http.StatusOK {
		return errors.New(res.Status) // TODO: Proper errors based on what the server returns
	}

	return string(body), nil
}

func (c *Client) String() string {
	return fmt.Sprintf("<fxa.Client email=%s password=%s uid=%s sessionToken=%v keyFetchToken=%v>", c.email, c.password, c.uid, c.sessionToken, c.keyFetchToken)
}

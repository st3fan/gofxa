// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

package fxa

import (
	"crypto/dsa"
	"crypto/rand"
	"testing"
)

func Test_NewClient(t *testing.T) {
	client, err := NewClient("gofxa@sateh.com", "secret1234")
	if client == nil || err != nil {
		t.Error("Cannot create client: ", err)
	}
}

func generateRandomKey() (*dsa.PrivateKey, error) {
	params := new(dsa.Parameters)
	if err := dsa.GenerateParameters(params, rand.Reader, dsa.L1024N160); err != nil {
		return nil, err
	}
	priv := new(dsa.PrivateKey)
	priv.PublicKey.Parameters = *params
	if err := dsa.GenerateKey(priv, rand.Reader); err != nil {
		return nil, err
	}
	return priv, nil
}

func Test_Login(t *testing.T) {
	client, err := NewClient("gofxa@sateh.com", "secret1234")
	if client == nil || err != nil {
		t.Error("Cannot create client: ", err)
	}

	if err := client.Login(); err != nil {
		t.Error("Cannot login: ", err)
	}

	if err := client.FetchKeys(); err != nil {
		t.Error("Cannot login: ", err)
	}

	key, err := generateRandomKey()
	if err != nil {
		t.Error("Cannot generate key: ", err)
	}

	if _, err := client.SignCertificate(key); err != nil {
		t.Error("Cannot login: ", err)
	}
}

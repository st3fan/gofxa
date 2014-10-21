package fxa

import (
	"code.google.com/p/go.crypto/hkdf"
	"code.google.com/p/go.crypto/pbkdf2"
	"crypto/sha256"
	"io"
)

func quickStretchPassword(email, password string) []byte {
	salt := "identity.mozilla.com/picl/v1/quickStretch:" + email
	return pbkdf2.Key([]byte(password), []byte(salt), 1000, 32, sha256.New)
}

func deriveAuthPWFromQuickStretchedPassword(stretchedPassword []byte) ([]byte, error) {
	secret := make([]byte, sha256.Size)
	if _, err := io.ReadFull(hkdf.New(sha256.New, stretchedPassword, nil, []byte("identity.mozilla.com/picl/v1/authPW")), secret); err != nil {
		return nil, err
	}
	return secret, nil
}

func deriveUnwrapBKeyFromQuickStretchedPassword(stretchedPassword []byte) ([]byte, error) {
	secret := make([]byte, sha256.Size)
	if _, err := io.ReadFull(hkdf.New(sha256.New, stretchedPassword, nil, []byte("identity.mozilla.com/picl/v1/unwrapBKey")), secret); err != nil {
		return nil, err
	}
	return secret, nil
}

//func deriveResponseKeys() ([]byte, []byte) {
//}

type RequestCredentials struct {
	TokenId        []byte
	RequestHMACKey []byte
	RequestKey     []byte
}

func NewRequestCredentials(token []byte, name string) (*RequestCredentials, error) {
	secret := make([]byte, 3*sha256.Size)
	if _, err := io.ReadFull(hkdf.New(sha256.New, token, nil, []byte("identity.mozilla.com/picl/v1/"+name)), secret); err != nil {
		return nil, err
	}
	return &RequestCredentials{
		TokenId:        secret[0:32],
		RequestHMACKey: secret[32:64],
		RequestKey:     secret[64:96],
	}, nil
}

type AccountKeys struct {
	HMACKey []byte
	XORKey  []byte
}

func NewAccountKeys(requestKey []byte) (*AccountKeys, error) {
	secret := make([]byte, 3*sha256.Size)
	if _, err := io.ReadFull(hkdf.New(sha256.New, requestKey, nil, []byte("identity.mozilla.com/picl/v1/account/keys")), secret); err != nil {
		return nil, err
	}
	return &AccountKeys{
		HMACKey: secret[0:32],
		XORKey:  secret[32:96],
	}, nil
}

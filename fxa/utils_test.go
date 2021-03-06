// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

package fxa

import (
	"bytes"
	"testing"
)

func Test_quickStretchPassword(t *testing.T) {
	b := quickStretchPassword("text@example.com", "secret1234")
	expected := []byte{0xdf, 0x1d, 0x31, 0x12, 0x1e, 0xc7, 0xb4, 0xb2, 0xbe, 0xfc, 0x8b, 0x53, 0xaf, 0xfb, 0x1c, 0xdf, 0x6a, 0xd7, 0xcc, 0xb2, 0xa9, 0x8b, 0x7b, 0x77, 0x9c, 0x25, 0x6c, 0x7a, 0xe2, 0xbc, 0x95, 0x32}
	if !bytes.Equal(b, expected) {
		t.Errorf("Did not get expected value: %#v", b)
	}
}

func Test_deriveAuthPWFromQuickStretchedPassword(t *testing.T) {
	b, err := deriveAuthPWFromQuickStretchedPassword(quickStretchPassword("text@example.com", "secret1234"))
	if err != nil {
		t.Error(err)
	}
	expected := []byte{0x5f, 0xcd, 0xd0, 0x38, 0x10, 0x95, 0xbe, 0x23, 0xd, 0xd2, 0xc8, 0x3b, 0xf5, 0x9d, 0x10, 0x33, 0x84, 0xf5, 0x60, 0xc6, 0xb8, 0x36, 0x58, 0xf6, 0xb4, 0x59, 0x51, 0x35, 0x86, 0x7d, 0x3f, 0x6e}
	if !bytes.Equal(b, expected) {
		t.Errorf("Did not get expected value: %#v", b)
	}
}

func Test_deriveUnwrapBKeyFromQuickStretchedPassword(t *testing.T) {
	b, err := deriveUnwrapBKeyFromQuickStretchedPassword(quickStretchPassword("text@example.com", "secret1234"))
	if err != nil {
		t.Error(err)
	}
	expected := []byte{0x96, 0xc6, 0x90, 0xa6, 0x50, 0xee, 0xa, 0xa8, 0x16, 0x29, 0x78, 0xb, 0x1a, 0xb, 0x9e, 0x25, 0x8f, 0xc2, 0x54, 0x4c, 0xdc, 0x99, 0xc5, 0x10, 0x57, 0x3e, 0xce, 0x27, 0x6b, 0xc4, 0xa7, 0xd1}
	if !bytes.Equal(b, expected) {
		t.Errorf("Did not get expected value: %#v", b)
	}
}

func Test_newRequestCredentials(t *testing.T) {
	token := []byte{0xe6, 0x7e, 0x3d, 0xd1, 0x54, 0x92, 0x69, 0x83, 0x10, 0xb5, 0xc1, 0xd5, 0xd3, 0x25, 0x9c, 0x93, 0xb4, 0x4a, 0xcf, 0xce, 0x1d, 0x4d, 0x94, 0x4c, 0xdd, 0x30, 0x4e, 0x2c, 0x54, 0xbb, 0x43, 0xb8}
	rc, err := newRequestCredentials(token, "sessionToken")
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(rc.TokenId, []byte{0x17, 0x05, 0xc2, 0x4d, 0x98, 0x16, 0xcb, 0xd6, 0x50, 0x68, 0xa1, 0xdc, 0xd7, 0x5e, 0xed, 0xee, 0x06, 0xcd, 0xaf, 0xd9, 0x7d, 0x4d, 0xfa, 0xaf, 0x81, 0x64, 0x7b, 0x22, 0xf6, 0x0a, 0x88, 0x5e}) {
		t.Errorf("Did not get expected TokenId")
	}
	if !bytes.Equal(rc.RequestHMACKey, []byte{0xfa, 0xf2, 0xd7, 0x4a, 0x00, 0x05, 0x8c, 0x9d, 0x7f, 0x3d, 0x9e, 0xb5, 0x83, 0x22, 0xa3, 0x63, 0xcd, 0x96, 0x4e, 0xef, 0xf1, 0x6b, 0x00, 0xba, 0x86, 0xf5, 0x08, 0xdb, 0xda, 0xa6, 0x8d, 0x84}) {
		t.Errorf("Did not get expected RequestHMACKey")
	}
	if !bytes.Equal(rc.RequestKey, []byte{0x44, 0xe2, 0xd0, 0xf0, 0x7c, 0x8a, 0x25, 0x3c, 0x79, 0x93, 0xe8, 0x29, 0x9f, 0x19, 0x09, 0xa2, 0x66, 0xbd, 0xbf, 0x2b, 0xb6, 0x59, 0xdb, 0x9d, 0xd8, 0xe1, 0x70, 0xdf, 0x06, 0xeb, 0xc2, 0xf0}) {
		t.Errorf("Did not get expected RequestKey")
	}
}

func Test_newAccountKeys(t *testing.T) {
	requestKey := []byte{0x44, 0xe2, 0xd0, 0xf0, 0x7c, 0x8a, 0x25, 0x3c, 0x79, 0x93, 0xe8, 0x29, 0x9f, 0x19, 0x09, 0xa2, 0x66, 0xbd, 0xbf, 0x2b, 0xb6, 0x59, 0xdb, 0x9d, 0xd8, 0xe1, 0x70, 0xdf, 0x06, 0xeb, 0xc2, 0xf0}
	ak, err := newAccountKeys(requestKey)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(ak.HMACKey, []byte{0xee, 0xba, 0xfc, 0x48, 0x77, 0x1e, 0x38, 0x37, 0x37, 0xbd, 0x6d, 0x7f, 0xd8, 0xe2, 0xe0, 0x9a, 0x4, 0x63, 0x85, 0x9d, 0x96, 0xab, 0x68, 0x63, 0xf7, 0x57, 0xdc, 0xcb, 0x5e, 0x30, 0xd2, 0x1}) {
		t.Errorf("Did not get expected HMACKey: %#v", ak.HMACKey)
	}
	if !bytes.Equal(ak.XORKey, []byte{0xe0, 0xe, 0xf3, 0xd3, 0xe3, 0xaa, 0xea, 0xf, 0x6e, 0x22, 0xaf, 0x8b, 0x80, 0xa1, 0xed, 0x2d, 0x8f, 0xdc, 0x73, 0x18, 0xb2, 0x27, 0x69, 0x54, 0xba, 0x36, 0xa0, 0x61, 0x97, 0x80, 0x17, 0xe0, 0xc4, 0xf3, 0xd7, 0xc1, 0xc1, 0x7d, 0x54, 0x91, 0x9, 0x6d, 0x3c, 0x3f, 0xa0, 0x46, 0xdd, 0xf4, 0x56, 0x47, 0x7c, 0x47, 0xf2, 0xd9, 0xce, 0x8f, 0xab, 0x82, 0x79, 0x3, 0x28, 0x37, 0xe5, 0xe8}) {
		t.Errorf("Did not get expected XORKey: %#v", ak.XORKey)
	}
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

package fxa

import (
	"net/url"
	"testing"
)

func Test_portForURL_HTTP(t *testing.T) {
	u, _ := url.Parse("http://www.example.com/index.html")
	if port, err := portForURL(u); err != nil || port != 80 {
		t.Error()
	}
}

func Test_portForURL_HTTPS(t *testing.T) {
	u, _ := url.Parse("https://www.example.com/index.html")
	if port, err := portForURL(u); err != nil || port != 443 {
		t.Error()
	}
}

func Test_portForURL_Custom(t *testing.T) {
	u, _ := url.Parse("http://www.example.com:8080/index.html")
	if port, err := portForURL(u); err != nil || port != 8080 {
		t.Error()
	}
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

package fxa

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
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

func Test_hawkPayloadHash(t *testing.T) {
	body := "Thank you for flying Hawk"
	request, _ := http.NewRequest("POST", "http://example.com:8000/resource/1?b=1&a=2", strings.NewReader(body))
	request.Header.Set("Content-Type", "text/plain")
	if hash, err := hawkPayloadHash(request, strings.NewReader(body)); err != nil || hash != "Yi9LfIIFRtBEPt74PVmbTF/xVAwPn7ub15ePICfgnuY=" {
		t.Error()
	}
}

func Test_hawkSignature_GET(t *testing.T) {
	request, _ := http.NewRequest("GET", "http://example.com:8000/resource/1?b=1&a=2", nil)
	signature, err := hawkSignature(request, "", []byte("werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"), time.Unix(1353832234, 0), "j4h3g2", "some-app-ext-data")
	if err != nil || signature != "6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=" {
		t.Error("Request signature failure: ", err, signature)
	}
}

func Test_hawkSignature_POST(t *testing.T) {
	body := "Thank you for flying Hawk"
	request, _ := http.NewRequest("POST", "http://example.com:8000/resource/1?b=1&a=2", strings.NewReader(body))
	request.Header.Set("Content-Type", "text/plain")

	hash, err := hawkPayloadHash(request, strings.NewReader(body))
	if err != nil || hash != "Yi9LfIIFRtBEPt74PVmbTF/xVAwPn7ub15ePICfgnuY=" {
		t.Error("Payload hash failure")
	}

	signature, err := hawkSignature(request, hash, []byte("werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"), time.Unix(1353832234, 0), "j4h3g2", "some-app-ext-data")
	if err != nil || signature != "aSe1DERmZuRl3pI36/9BdZmnErTw3sNzOOAUlfeKjVw=" {
		t.Error("Request signature failure: ", err, signature)
	}
}

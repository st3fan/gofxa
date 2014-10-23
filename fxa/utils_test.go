// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

package fxa

import (
	"bytes"
	"testing"
)

func Test_quickStretchPassword(t *testing.T) {
	expected := []byte{223, 29, 49, 18, 30, 199, 180, 178, 190, 252, 139, 83, 175, 251, 28, 223, 106, 215, 204, 178, 169, 139, 123, 119, 156, 37, 108, 122, 226, 188, 149, 50}
	if !bytes.Equal(quickStretchPassword("text@example.com", "secret1234"), expected) {
		t.Error(quickStretchPassword("text@example.com", "secret1234"))
	}
}

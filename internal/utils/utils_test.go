// Copyright Louis Royer and the NextMN contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT

package utils

import (
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestFromIPv6(t *testing.T) {
	res, err := FromIPv6(netip.MustParseAddr("::ff:192.168.0.1").As16(), 128-8*4, 4)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(res, []byte{192, 168, 0, 1}); diff != "" {
		t.Error(diff)
	}
	res, err = FromIPv6(netip.MustParseAddr("ff00::").As16(), 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(res, []byte{0xFE}); diff != "" {
		t.Error(diff)
	}
	res, err = FromIPv6(netip.MustParseAddr("ff55::").As16(), 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(res, []byte{0xFD, 0x54}); diff != "" {
		t.Error(diff)
	}
	res, err = FromIPv6(netip.MustParseAddr("0ff5:5000::").As16(), 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(res, []byte{0xFF, 0x55}); diff != "" {
		t.Error(diff)
	}
}

func TestAppendTo16(t *testing.T) {
	b1 := [16]byte{
		0xFF, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	res1, err := AppendTo16(b1, 8, []byte{0x00, 0xAA})
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(res1, [16]byte{
		0xFF, 0x00, 0xAA, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}); diff != "" {
		t.Error(diff)
	}

	b2 := [16]byte{
		0xE0, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	res2, err := AppendTo16(b2, 3, []byte{0x00, 0xAA, 0xFF})
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(res2, [16]byte{
		0xE0, 0x15, 0x5F, 0xE0,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}); diff != "" {
		t.Error(diff)
	}
}

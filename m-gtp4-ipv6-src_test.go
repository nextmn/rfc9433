// Copyright Louis Royer and the NextMN contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT

package rfc9433_test

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/nextmn/rfc9433"

	"github.com/google/go-cmp/cmp"
)

func ExampleMGTP4IPv6Src() {
	if src, ok := rfc9433.MGTP4IPv6SrcFrom(
		netip.MustParsePrefix("3fff::/20"),
		netip.MustParseAddr("203.0.113.1").As4(),
	); ok {
		src.AsAddr().AsSlice()
		// ...
		if fields, err := rfc9433.ParseMGTP4IPv6Src(src.AsAddr().As16(), 20); err != nil {
			panic(err)
		} else {
			fields.IPv4()
		}
	}
}

func TestMGTP4IPv6Src(t *testing.T) {
	ip_addr := [16]byte{
		0x20, 0x01, 0xDB, 0x08,
		192, 0, 2, 1,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	e, err := rfc9433.ParseMGTP4IPv6Src(ip_addr, 32)
	if err != nil {
		t.Fatal(err)
	}
	if e.IPv4().Compare(netip.MustParseAddr("192.0.2.1")) != 0 {
		t.Fatalf("Cannot extract ipv4 correctly: %s", e.IPv4())
	}
	ip_addr2, ok := rfc9433.MGTP4IPv6SrcFrom(netip.MustParsePrefix("fd00:1:1::/48"), [4]byte{10, 0, 4, 1})
	if !ok {
		t.Fatal("Could not create MGTP4IPv6Src")
	}
	b := ip_addr2.AsAddr().As16()
	res2 := [16]byte{
		0xfd, 0x00, 0x00, 0x01, 0x00, 0x01,
		10, 0, 4, 1,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	fmt.Println(b)
	fmt.Println(res2)
	if diff := cmp.Diff(b, res2); diff != "" {
		t.Error(diff)
	}

}

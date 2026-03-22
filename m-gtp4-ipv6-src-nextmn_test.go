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

func ExampleMGTP4IPv6SrcNextMN() {
	if src, ok := rfc9433.MGTP4IPv6SrcNextMNFrom(
		netip.MustParsePrefix("3fff::/20"),
		netip.MustParseAddr("203.0.113.1").As4(),
		1337,
	); ok {
		src.AsAddr().AsSlice()
		// ...
	}
}

func TestMGTP4IPv6SrcNextMN(t *testing.T) {
	ip_addr := [16]byte{
		0x20, 0x01, 0xDB, 0x08,
		192, 0, 2, 1,
		0x01, 0x23,
		0x55, 0x55, 0x55, 0x55, 0x55,
		32,
	}

	e, err := rfc9433.ParseMGTP4IPv6SrcNextMN(ip_addr)
	if err != nil {
		t.Fatal(err)
	}
	if e.IPv4().Compare(netip.MustParseAddr("192.0.2.1")) != 0 {
		t.Fatalf("Cannot extract ipv4 correctly: %s", e.IPv4())
	}
	if e.UDPPortNumber() != 0x0123 {
		t.Fatalf("Cannot extract udp port number correctly: %x", e.UDPPortNumber())
	}
	ip_addr2, ok := rfc9433.MGTP4IPv6SrcNextMNFrom(netip.MustParsePrefix("fd00:1:1::/48"), [4]byte{10, 0, 4, 1}, 0x1234)
	if !ok {
		t.Fatal("Could not create MGTP4IPv6SrcNextMN")
	}
	b := ip_addr2.AsAddr().As16()
	res2 := [16]byte{
		0xfd, 0x00, 0x00, 0x01, 0x00, 0x01,
		10, 0, 4, 1,
		0x12, 0x34,
		0x00, 0x00, 0x00,
		48,
	}
	fmt.Println(b)
	fmt.Println(res2)
	if diff := cmp.Diff(b, res2); diff != "" {
		t.Error(diff)
	}

}

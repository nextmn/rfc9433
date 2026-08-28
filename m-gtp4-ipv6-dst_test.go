// Copyright Louis Royer and the NextMN contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT

package rfc9433_test

import (
	"fmt"
	"net/netip"

	"github.com/nextmn/rfc9433"
)

func ExampleMGTP4IPv6Dst() {
	if dst, ok := rfc9433.MGTP4IPv6DstFrom(
		netip.MustParsePrefix("3fff::/20"),
		netip.MustParseAddr("203.0.113.1").As4(),
		rfc9433.ArgsMobSessionFrom(0, false, false, 1337).As5(),
	); ok {
		fmt.Println("Segment:", dst.AsAddr())
		// ...
		fmt.Println("Embedded IP Address:", dst.IPv4())
		fmt.Println("PDU Session ID (TEID):", dst.ArgsMobSession().PDUSessionID())
	}
	// Output:
	// Segment: 3fff:cb0:710:1000:0:5390::
	// Embedded IP Address: 203.0.113.1
	// PDU Session ID (TEID): 1337
}

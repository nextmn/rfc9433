// Copyright Louis Royer and the NextMN contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT

package rfc9433_test

import (
	"net/netip"

	"github.com/nextmn/rfc9433"
)

func ExampleMGTP4IPv6Dst() {
	dst := rfc9433.NewMGTP4IPv6Dst(
		netip.MustParsePrefix("3fff::/20"),
		netip.MustParseAddr("203.0.113.1").As4(),
		rfc9433.ArgsMobSessionFrom(0, false, false, 1).As5(),
	)
	dst.Marshal()
}

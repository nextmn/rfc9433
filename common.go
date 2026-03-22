// Copyright Louis Royer and the NextMN contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT

package rfc9433

import (
	"net/netip"
)

// gtp4Base type to store values for GTP4
type gtp4Base struct {
	prefix netip.Prefix // prefix in canonical form
	ipv4   [4]byte
}

// IPv4 returns the IPv4 Address encoded.
func (g gtp4Base) IPv4() netip.Addr {
	return netip.AddrFrom4(g.ipv4)
}

// Prefix returns the IPv6 Prefix.
func (g gtp4Base) Prefix() netip.Prefix {
	return g.prefix
}

// Copyright Louis Royer and the NextMN contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT

package rfc9433

import (
	"errors"
	"net/netip"

	"github.com/nextmn/rfc9433/internal/utils"
)

const (
	// "IPv6 Length" field
	ipv6LenEncodingSizeBit = 7                                      // size of the field in bits
	ipv6LenEncodingPosBit  = 0                                      // position from right of the byte in bits
	ipv6LenEncodingPosByte = 15                                     // position from left in bytes
	ipv6LenEncodingMask    = (0xFF >> (8 - ipv6LenEncodingSizeBit)) // mask (decoding: after shift to right; encoding before shift to left)
)

// RFC 9433, section 6.6 (End.M.GTP4.E):
// The IPv6 Source Address has the following format:
//
//	0                                                         127
//	+----------------------+--------+--------------------------+
//	|  Source UPF Prefix   |IPv4 SA | any bit pattern(ignored) |
//	+----------------------+--------+--------------------------+
//	         128-a-b            a                  b
//	          Figure 10: IPv6 SA Encoding for End.M.GTP4.E
type MGTP4IPv6Src struct {
	gtp4Base
}

// MGTP4IPv6SrcFrom creates a new MGTP4IPv6Src.
// If prefix is invalid or larger than 96 bits, MGTP4Ipv6SrcFrom returns [MGTP4IPv6Src]{}, false
func MGTP4IPv6SrcFrom(prefix netip.Prefix, ipv4 [4]byte) (MGTP4IPv6Src, bool) {
	bits := prefix.Bits()
	if bits == -1 || bits+8*4 > 8*16 {
		return MGTP4IPv6Src{}, false
	}
	return MGTP4IPv6Src{
		prefix: prefix.Masked(),
		ipv4:   ipv4,
	}, true
}

// ParseMGTP4IPv6SrcNextMN parses a given IPv6 source address without any specific bit pattern into a MGTP4IPv6Src
func ParseMGTP4IPv6Src(addr [16]byte, prefixLen int) (MGTP4IPv6Src, error) {
	if prefixLen+8*4 > 8*16 {
		// Prefix is too big: no space for IPv4 Address
		return MGTP4IPv6Src{}, ErrPrefixLength
	}

	// prefix extraction
	a := netip.AddrFrom16(addr)
	prefix := netip.PrefixFrom(a, prefixLen).Masked()
	if prefix.Bits() == -1 {
		// Prefix is too small (zero or less)
		return MGTP4IPv6Src{}, ErrPrefixLength
	}

	// ipv4 extraction
	var ipv4 [4]byte
	if src, err := utils.FromIPv6(addr, prefixLen, 4); err != nil {
		return MGTP4IPv6Src{}, errors.Join(ErrPrefixLength, err)
	} else {
		copy(ipv4[:], src[:4])
	}

	return MGTP4IPv6Src{
		prefix: prefix.Masked(),
		ipv4:   ipv4,
	}, nil
}

// AsAddr returns the [netip.Addr] representation of an MGTP4IPv6Src
func (m MGTP4IPv6Src) AsAddr() netip.Addr {
	bits := m.prefix.Bits()
	if bits == -1 {
		return netip.Addr{}
	}

	// add ipv4
	addr := m.prefix.Addr().As16()
	addr, err := utils.AppendTo16(addr, bits, netip.AddrFrom4(m.ipv4).AsSlice())
	if err != nil {
		return netip.Addr{}
	}

	return netip.AddrFrom16(addr)
}

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

// RFC 9433, section 6.6 (End.M.GTP4.E):
// The End.M.GTP.E SID in S has the following format:
//
//	0                                                         127
//	+-----------------------+-------+----------------+---------+
//	|  SRGW-IPv6-LOC-FUNC   |IPv4DA |Args.Mob.Session|0 Padded |
//	+-----------------------+-------+----------------+---------+
//	       128-a-b-c            a            b           c
//	Figure 9: End.M.GTP4.E SID Encoding
type MGTP4IPv6Dst struct {
	gtp4Base
	argsMobSession [5]byte
}

// MGTP4IPv6DstFrom creates a MGTP4IPv6Dst.
// If prefix is invalid or larger than 56 bits, MGTP4Ipv6DstFrom returns [MGTP4IPv6Dst]{}, false
func MGTP4IPv6DstFrom(prefix netip.Prefix, ipv4 [4]byte, argsMobSession [5]byte) (MGTP4IPv6Dst, bool) {
	bits := prefix.Bits()
	if bits == -1 || bits+(4*8)+(5*8) > 128 {
		return MGTP4IPv6Dst{}, false
	}
	return MGTP4IPv6Dst{
		prefix:         prefix.Masked(),
		ipv4:           ipv4,
		argsMobSession: argsMobSession,
	}, true
}

// ParseMGTP4IPv6Dst parses a given byte sequence into a MGTP4IPv6Dst according to the given prefixLength.
func ParseMGTP4IPv6Dst(addr [16]byte, prefixLength int) (MGTP4IPv6Dst, error) {
	// prefix extraction
	a := netip.AddrFrom16(addr)
	prefix := netip.PrefixFrom(a, prefixLength).Masked()
	if prefix.Bits() == -1 {
		return MGTP4IPv6Dst{}, ErrPrefixLength
	}

	// ipv4 extraction
	var ipv4 [4]byte
	if dst, err := utils.FromIPv6(addr, prefixLength, 4); err != nil {
		return MGTP4IPv6Dst{}, errors.Join(ErrPrefixLength, err)
	} else {
		copy(ipv4[:], dst[:4])
	}

	// argMobSession extraction
	var argsMobSession [5]byte
	if argsMobSessionSlice, err := utils.FromIPv6(addr, prefixLength+8*4, argsSessionSizeByte); err != nil {
		return MGTP4IPv6Dst{}, errors.Join(ErrPrefixLength, err)
	} else {
		copy(argsMobSession[:], argsMobSessionSlice[:5])
	}
	return MGTP4IPv6Dst{
		prefix:         prefix,
		ipv4:           ipv4,
		argsMobSession: argsMobSession,
	}, nil
}

// IPv4 returns the IPv4 Address encoded in the MGTP4IPv6Dst.
func (m MGTP4IPv6Dst) IPv4() netip.Addr {
	return netip.AddrFrom4(m.ipv4)
}

// ArgsMobSession returns the ArgsMobSession encoded in the MGTP4IPv6Dst.
func (m MGTP4IPv6Dst) ArgsMobSession() ArgsMobSession {
	return ArgsMobSessionFrom5(m.argsMobSession)
}

// Prefix returns the IPv6 Prefix for this MGTP4IPv6Dst.
func (m MGTP4IPv6Dst) Prefix() netip.Prefix {
	return m.prefix
}

// AsAddr returns the [netip.Addr] representation of an MGTP4IPv6Dst
func (m MGTP4IPv6Dst) AsAddr() netip.Addr {
	bits := m.prefix.Bits()
	if bits == -1 {
		return netip.Addr{}
	}
	addr := m.prefix.Addr().As16()
	addr, err := utils.AppendTo16(addr, bits, netip.AddrFrom4(m.ipv4).AsSlice())
	if err != nil {
		return netip.Addr{}
	}
	addr, err = utils.AppendTo16(addr, bits+8*4, ArgsMobSessionFrom5(m.argsMobSession).AsSlice())
	if err != nil {
		return netip.Addr{}
	}

	return netip.AddrFrom16(addr)
}

// String returns the string form of an MGTP4IPv6Dst.
func (m MGTP4IPv6Dst) String() string {
	return m.AsAddr().String()
}

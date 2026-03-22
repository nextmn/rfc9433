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
	prefix         netip.Prefix // prefix in canonical form
	ipv4           [4]byte
	argsMobSession [5]byte
}

// NewMGTP4IPv6Dst creates a new MGTP4IPv6Dst.
func NewMGTP4IPv6Dst(prefix netip.Prefix, ipv4 [4]byte, argsMobSession [5]byte) *MGTP4IPv6Dst {
	return &MGTP4IPv6Dst{
		prefix:         prefix.Masked(),
		ipv4:           ipv4,
		argsMobSession: argsMobSession,
	}
}

// ParseMGTP4IPv6Dst parses a given byte sequence into a MGTP4IPv6Dst according to the given prefixLength.
func ParseMGTP4IPv6Dst(ipv6Addr [16]byte, prefixLength int) (*MGTP4IPv6Dst, error) {
	// prefix extraction
	a := netip.AddrFrom16(ipv6Addr)
	prefix := netip.PrefixFrom(a, prefixLength).Masked()
	if prefix.Bits() == -1 {
		return nil, ErrPrefixLength
	}

	// ipv4 extraction
	var ipv4 [4]byte
	if src, err := utils.FromIPv6(ipv6Addr, prefixLength, 4); err != nil {
		return nil, errors.Join(ErrPrefixLength, err)
	} else {
		copy(ipv4[:], src[:4])
	}

	// argMobSession extraction
	var argsMobSession [5]byte
	argsMobSessionSlice, err := utils.FromIPv6(ipv6Addr, prefixLength+8*4, argsSessionSizeByte)
	if err != nil {
		return nil, errors.Join(ErrPrefixLength, err)
	} else {
		copy(argsMobSession[:], argsMobSessionSlice[:5])
	}
	return &MGTP4IPv6Dst{
		prefix:         prefix,
		ipv4:           ipv4,
		argsMobSession: argsMobSession,
	}, nil
}

// IPv4 returns the IPv4 Address encoded in the MGTP4IPv6Dst.
func (m *MGTP4IPv6Dst) IPv4() netip.Addr {
	return netip.AddrFrom4(m.ipv4)
}

// ArgsMobSession returns the ArgsMobSession encoded in the MGTP4IPv6Dst.
func (m *MGTP4IPv6Dst) ArgsMobSession() ArgsMobSession {
	return ArgsMobSessionFrom5(m.argsMobSession)
}

// Prefix returns the IPv6 Prefix for this MGTP4IPv6Dst.
func (m *MGTP4IPv6Dst) Prefix() netip.Prefix {
	return m.prefix
}

// MarshalLen returns the serial length of MGTP4IPv6Dst.
func (m *MGTP4IPv6Dst) MarshalLen() int {
	return 16 // size of an IPv6 packet
}

// Marshal returns the byte sequence generated from MGTP4IPv6Dst.
func (m *MGTP4IPv6Dst) Marshal() ([]byte, error) {
	b := make([]byte, m.MarshalLen())
	if err := m.MarshalTo(b); err != nil {
		return nil, err
	}
	return b, nil
}

// MarshalTo puts the byte sequence in the byte array given as b.
// warning: no caching is done, this result will be recomputed at each call
func (m *MGTP4IPv6Dst) MarshalTo(b []byte) error {
	if len(b) < m.MarshalLen() {
		return ErrTooShortToMarshal
	}

	// get offset
	bits := m.prefix.Bits()
	if bits == -1 {
		return ErrPrefixLength
	}

	// init ipv6 with the prefix
	prefix := m.prefix.Addr().As16()
	copy(b, prefix[:])

	// add ipv4
	ipv4 := netip.AddrFrom4(m.ipv4).AsSlice()
	if err := utils.AppendToSlice(b, bits, ipv4); err != nil {
		return err
	}

	// add Args-Mob-Session
	argsMobSession := ArgsMobSessionFrom5(m.argsMobSession).AsSlice()
	if err := utils.AppendToSlice(b, bits+8*4, argsMobSession); err != nil {
		return errors.Join(ErrPrefixLength, err)
	}

	return nil
}

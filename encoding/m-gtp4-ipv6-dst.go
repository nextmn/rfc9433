// Copyright 2023 Louis Royer and the NextMN contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT

package encoding

import (
	"net/netip"

	"github.com/nextmn/rfc9433/encoding/errors"
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
	argsMobSession *ArgsMobSession
}

// NewMGTP4IPv6Dst creates a new MGTP4IPv6Dst.
func NewMGTP4IPv6Dst(prefix netip.Prefix, ipv4 [4]byte, a *ArgsMobSession) *MGTP4IPv6Dst {
	return &MGTP4IPv6Dst{
		prefix:         prefix.Masked(),
		ipv4:           ipv4,
		argsMobSession: a,
	}
}

// ParseMGTP4IPv6Dst parses a given byte sequence into a MGTP4IPv6Dst according to the given prefixLength.
func ParseMGTP4IPv6Dst(ipv6Addr [16]byte, prefixLength uint) (*MGTP4IPv6Dst, error) {
	// prefix extraction
	a := netip.AddrFrom16(ipv6Addr)
	prefix := netip.PrefixFrom(a, int(prefixLength)).Masked()

	// ipv4 extraction
	var ipv4 [4]byte
	if src, err := utils.FromIPv6(ipv6Addr, prefixLength, 4); err != nil {
		return nil, err
	} else {
		copy(ipv4[:], src[:4])
	}

	// argMobSession extraction
	argsMobSessionSlice, err := utils.FromIPv6(ipv6Addr, prefixLength+8*4, 5)
	argsMobSession, err := ParseArgsMobSession(argsMobSessionSlice)
	if err != nil {
		return nil, err
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
func (m *MGTP4IPv6Dst) ArgsMobSession() *ArgsMobSession {
	return m.argsMobSession
}

// QFI returns the QFI encoded in the MGTP4IPv6Dst's ArgsMobSession.
func (m *MGTP4IPv6Dst) QFI() uint8 {
	return m.argsMobSession.QFI()
}

// R returns the R bit encoded in the MGTP4IPv6Dst's ArgsMobSession.
func (m *MGTP4IPv6Dst) R() bool {
	return m.argsMobSession.R()
}

// U returns the U bit encoded in the MGTP4IPv6Dst's ArgsMobSession.
func (m *MGTP4IPv6Dst) U() bool {
	return m.argsMobSession.U()
}

// PDUSessionID returns the PDUSessionID for this MGTP4IPv6Dst's ArgsMobSession.
func (m *MGTP4IPv6Dst) PDUSessionID() uint32 {
	return m.argsMobSession.PDUSessionID()
}

// Prefix returns the IPv6 Prefix for this MGTP4IPv6Dst.
func (m *MGTP4IPv6Dst) Prefix() netip.Prefix {
	return m.prefix
}

// MarshalLen returns the serial length of MGTP4IPv6Dst.
func (m *MGTP4IPv6Dst) MarshalLen() int {
	return 16
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
		return errors.ErrTooShortToMarshal
	}
	// init ipv6 with the prefix
	prefix := m.prefix.Addr().As16()
	copy(b, prefix[:])

	ipv4 := netip.AddrFrom4(m.ipv4).AsSlice()
	bits := m.prefix.Bits()
	if bits == -1 {
		return errors.ErrPrefixLength
	}

	// add ipv4
	if err := utils.AppendToSlice(b, uint(bits), ipv4); err != nil {
		return err
	}
	argsMobSessionB, err := m.argsMobSession.Marshal()
	if err != nil {
		return err
	}
	// add Args-Mob-Session
	if err := utils.AppendToSlice(b, uint(bits+8*4), argsMobSessionB); err != nil {
		return err
	}
	return nil
}

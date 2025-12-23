// Copyright Louis Royer and the NextMN contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT

package encoding

import (
	"encoding/binary"
	"net/netip"

	"github.com/nextmn/rfc9433/encoding/errors"
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
//
// With NextMN implementation, we choose to deviate from the RFC
// because RFC's proposal doesn't allow to retrieve
// the IPv4 SA without knowing the prefix length,
// which may be different for 2 packets issued from 2 different headends.
//
// To allow the endpoint to be stateless, we need to know the prefix.
// We propose to encode it on the 7 last bits of the IPv6 SA.
//
// The other option would have been to directly put the IPv4 SA at the end of the IPv6 SA (bytes 12 to 15),
// but this would imply matching on /128 if the IPv4 SA is used for source routing purpose,
// and thus breaking compatibility with future new patterns.
//
// We also introduce a new field that will carry the source UDP port to be used in the newly created GTP4 packet.
//
// This field is intended to help load balancing, as specified in [TS 129.281, section 4.4.2.0]:
//
// "For the GTP-U messages described below (other than the Echo Response message, see clause 4.4.2.2), the UDP Source Port
// or the Flow Label field (see IETF RFC 6437) should be set dynamically by the sending GTP-U entity to help
// balancing the load in the transport network".
//
// Since the headend has a better view than End.M.GTP4.E on
// the origin of the flows, and can be helped by the control plane,
// it makes sense to generate the source port number on headend side,
// and to carry it during transit through SR domain.
//
// Note: even with this proposal, the remaining space (73 bits) is bigger
// than what remains for LOC+FUNC in the SID (56 bits).
//
//	0                                                                                              127
//	+----------------------+-----------+-----------------+--------------------------+---------------+
//	|  Source UPF Prefix   |  IPv4 SA  | UDP Source Port | any bit pattern(ignored) | Prefix length |
//	+----------------------+-----------+-----------------+--------------------------+---------------+
//	    128-a-(b1+b2+b3)    a (32 bits)    b1 (16 bits)                 b2              b3 (7 bits)
//	        IPv6 SA Encoding for End.M.GTP4.E in NextMN
//
// [TS 129.281, section 4.4.2.0]: https://www.etsi.org/deliver/etsi_ts/129200_129299/129281/17.04.00_60/ts_129281v170400p.pdf#page=16
type MGTP4IPv6Src struct {
	prefix netip.Prefix // prefix in canonical form
	ipv4   [4]byte
	udp    uint16
}

// NewMGTP4IPv6Src creates a new MGTP4IPv6Src
func NewMGTP4IPv6Src(prefix netip.Prefix, ipv4 [4]byte, udpPortNumber uint16) *MGTP4IPv6Src {
	return &MGTP4IPv6Src{
		prefix: prefix.Masked(),
		ipv4:   ipv4,
		udp:    udpPortNumber,
	}
}

// ParseMGTP4IPv6SrcNextMN parses a given IPv6 source address with NextMN bit pattern into a MGTP4IPv6Src
func ParseMGTP4IPv6SrcNextMN(addr [16]byte) (*MGTP4IPv6Src, error) {
	// Prefix length extraction
	prefixLen := uint(ipv6LenEncodingMask & (addr[ipv6LenEncodingPosByte] >> ipv6LenEncodingPosBit))

	r, err := ParseMGTP4IPv6Src(addr, prefixLen)
	if err != nil {
		return nil, err
	}

	if prefixLen+8*4+16+ipv6LenEncodingSizeBit > 8*16 {
		// Prefix is too big: no space for UDP Port and "IPv6 Prefix length"
		return nil, errors.ErrOutOfRange
	}
	// udp port extraction
	if src, err := utils.FromIPv6(addr, prefixLen+8*4, 2); err != nil {
		return nil, err
	} else {
		var udp [2]byte
		copy(udp[:], src[:2])
		r.udp = binary.BigEndian.Uint16([]byte{udp[0], udp[1]})
	}
	return r, nil
}

// ParseMGTP4IPv6SrcNextMN parses a given IPv6 source address without any specific bit pattern into a MGTP4IPv6Src
func ParseMGTP4IPv6Src(addr [16]byte, prefixLen uint) (*MGTP4IPv6Src, error) {
	if prefixLen == 0 {
		// even if globally routable IPv6 Prefix size cannot currently be less than 32 (per ICANN policy),
		// nothing prevent the use of such prefix with ULA (fc00::/7)
		// or, in the future, a prefix from a currently not yet allocated address block.
		return nil, errors.ErrPrefixLength
	}
	if prefixLen+8*4 > 8*16 {
		// Prefix is too big: no space for IPv4 Address
		return nil, errors.ErrOutOfRange
	}
	// prefix extraction
	a := netip.AddrFrom16(addr)
	prefix := netip.PrefixFrom(a, int(prefixLen)).Masked()

	// ipv4 extraction
	var ipv4 [4]byte
	if src, err := utils.FromIPv6(addr, prefixLen, 4); err != nil {
		return nil, err
	} else {
		copy(ipv4[:], src[:4])
	}

	return &MGTP4IPv6Src{
		prefix: prefix,
		ipv4:   ipv4,
	}, nil
}

// IPv4 returns the IPv4 Address encoded in the MGTP4IPv6Src.
func (m *MGTP4IPv6Src) IPv4() netip.Addr {
	return netip.AddrFrom4(m.ipv4)
}

// UDPPortNumber returns the UDP Port Number encoded in the MGTP4IPv6Src (0 if not set).
func (m *MGTP4IPv6Src) UDPPortNumber() uint16 {
	return m.udp
}

// MarshalLen returns the serial length of MGTP4IPv6Src.
func (m *MGTP4IPv6Src) MarshalLen() int {
	return 16
}

// Marshal returns the byte sequence generated from MGTP4IPv6Src.
func (m *MGTP4IPv6Src) Marshal() ([]byte, error) {
	b := make([]byte, m.MarshalLen())
	if err := m.MarshalTo(b); err != nil {
		return nil, err
	}
	return b, nil
}

// MarshalTo puts the byte sequence in the byte array given as b.
// warning: no caching is done, this result will be recomputed at each call
func (m *MGTP4IPv6Src) MarshalTo(b []byte) error {
	if len(b) < m.MarshalLen() {
		return errors.ErrTooShortToMarshal
	}
	// init b with prefix
	prefix := m.prefix.Addr().As16()
	copy(b, prefix[:])

	ipv4 := netip.AddrFrom4(m.ipv4).AsSlice()
	udp := make([]byte, 2)
	binary.BigEndian.PutUint16(udp, m.udp)
	bits := m.prefix.Bits()
	if bits == -1 {
		return errors.ErrPrefixLength
	}

	// add ipv4
	if err := utils.AppendToSlice(b, uint(bits), ipv4); err != nil {
		return err
	}
	// add upd port
	if err := utils.AppendToSlice(b, uint(bits+8*4), udp); err != nil {
		return err
	}
	// add prefix length
	b[ipv6LenEncodingPosByte] = byte(bits)
	return nil
}

// Copyright Louis Royer and the NextMN contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT

package rfc9433

import (
	"encoding/binary"
	"net/netip"

	"github.com/nextmn/rfc9433/internal/utils"
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
type MGTP4IPv6SrcNextMN struct {
	gtp4Base
	udp uint16
}

// MGTP4IPv6SrcNextMNFrom creates a new MGTP4IPv6SrcNextMN.
// If prefix is invalid or larger than 55 bits, MGTP4Ipv6SrcFrom returns [MGTP4IPv6SrcNextMN]{}, false
func MGTP4IPv6SrcNextMNFrom(prefix netip.Prefix, ipv4 [4]byte, udpPortNumber uint16) (MGTP4IPv6SrcNextMN, bool) {
	bits := prefix.Bits()
	if bits == -1 || bits+(4*8)+(2*8)+7 > 128 {
		return MGTP4IPv6SrcNextMN{}, false
	}
	return MGTP4IPv6SrcNextMN{
		gtp4Base: gtp4Base{
			prefix: prefix.Masked(),
			ipv4:   ipv4,
		},
		udp: udpPortNumber,
	}, true
}

// ParseMGTP4IPv6SrcNextMN parses a given IPv6 source address with NextMN bit pattern into a MGTP4IPv6SrcNextMN.
func ParseMGTP4IPv6SrcNextMN(addr [16]byte) (MGTP4IPv6SrcNextMN, error) {
	// Prefix length extraction
	prefixLen := int(ipv6LenEncodingMask & (addr[ipv6LenEncodingPosByte] >> ipv6LenEncodingPosBit))
	if prefixLen+8*4+16+ipv6LenEncodingSizeBit > 8*16 {
		// Prefix is too big: no space for UDP Port and "IPv6 Prefix length"
		return MGTP4IPv6SrcNextMN{}, ErrPrefixLength
	}

	r, err := ParseMGTP4IPv6Src(addr, prefixLen)
	if err != nil {
		return MGTP4IPv6SrcNextMN{}, err
	}

	// udp port extraction
	var udp uint16
	if port, err := utils.FromIPv6(addr, prefixLen+8*4, 2); err != nil {
		return MGTP4IPv6SrcNextMN{}, err
	} else {
		udp = binary.BigEndian.Uint16([]byte{port[0], port[1]})
	}
	return MGTP4IPv6SrcNextMN{
		gtp4Base: r.gtp4Base,
		udp:      udp,
	}, nil
}

// UDPPortNumber returns the UDP Port Number encoded in the MGTP4IPv6SrcNextMN (0 if not set).
func (m MGTP4IPv6SrcNextMN) UDPPortNumber() uint16 {
	return m.udp
}

// AsAddr returns the [netip.Addr] representation of an MGTP4IPv6SrcNextMN
func (m MGTP4IPv6SrcNextMN) AsAddr() netip.Addr {
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

	// add upd port
	udp := make([]byte, 2)
	binary.BigEndian.PutUint16(udp, m.udp)
	addr, err = utils.AppendTo16(addr, bits+8*4, udp)
	if err != nil {
		return netip.Addr{}
	}

	// add prefix length
	addr[ipv6LenEncodingPosByte] = byte(bits)

	return netip.AddrFrom16(addr)
}

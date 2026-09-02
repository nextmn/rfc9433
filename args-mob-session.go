// Copyright Louis Royer and the NextMN contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT

package rfc9433

import (
	"encoding/binary"
	"strconv"
)

const (
	argsSessionSizeByte = 5

	// Field TEID
	teidSizeByte = 4                // size of the field in bytes
	teidSizeBit  = teidSizeByte * 8 // size of the field in bits
	teidPosByte  = 1                // position of the field from the left in bytes

	// Field QFI
	qfiSizeBit = 6                          // size of the field
	qfiPosBit  = 2                          // position from right of the byte in bits
	qfiPosByte = 0                          // position from left in bytes
	qfiMask    = (0xFF >> (8 - qfiSizeBit)) // mask (decoding: after shift to right; encoding before shift to left)

	// Field R
	rSizeBit = 1                        // size of the field
	rPosBit  = 1                        // position from right of the byte in bits
	rPosByte = 0                        // position from left in bytes
	rMask    = (0xFF >> (8 - rSizeBit)) // mask (decoding: after shift to right; encoding before shift to left)

	// Field U
	uSizeBit = 1                        // size of the field
	uPosBit  = 0                        // position from right of the byte in bits
	uPosByte = 0                        // position from left in bytes
	uMask    = (0xFF >> (8 - uSizeBit)) // mask (decoding: after shift to right; encoding before shift to left)
)

// Args.Mob.Session as defined in RFC 9433, section 6.1:
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|   QFI     |R|U|                PDU Session ID                                 |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	Figure 8: Args.Mob.Session Format
type ArgsMobSession struct {
	qfi          uint8  // QoS Flow Identifier (6 bits: the 2 Most Significant Bits are ignored)
	r            bool   // Reflective QoS Indication (1 bit)
	u            bool   // Unused and for future use (1 bit)
	pduSessionID uint32 // Identifier of PDU Session. The GTP-U equivalent is TEID (32 bits)
}

// ArgsMobSessionFrom5 parses the 5-byte byte slice as an ArgsMobSession.
func ArgsMobSessionFrom5(b [5]byte) ArgsMobSession {
	return ArgsMobSession{
		qfi:          qfiMask & (b[qfiPosByte] >> qfiPosBit),
		r:            (rMask&(b[rPosByte]>>rPosBit) == rMask),
		u:            (uMask&(b[uPosByte]>>uPosBit) == uMask),
		pduSessionID: binary.BigEndian.Uint32(b[teidPosByte : teidPosByte+teidSizeByte]),
	}
}

// ArgsMobSessionFromSlice parses the 5-byte byte slice as an ArgsMobSession.
// If slice length is not 5, ArgsMobsSession returns [ArgsMobSession]{}, false
func ArgsMobSessionFromSlice(slice []byte) (argsMobSession ArgsMobSession, ok bool) {
	if len(slice) != 5 {
		return ArgsMobSession{}, false
	}
	return ArgsMobSessionFrom5([5]byte{
		slice[0],
		slice[1],
		slice[2],
		slice[3],
		slice[4],
	}), true
}

// NewArgsMobSession creates an ArgsMobSession.
func ArgsMobSessionFrom(qfi uint8, r bool, u bool, pduSessionID uint32) ArgsMobSession {
	return ArgsMobSession{
		qfi:          (qfiMask & qfi),
		r:            r,
		u:            u,
		pduSessionID: pduSessionID,
	}
}

// QFI returns the Qos Flow Identifier for this ArgsMobSession.
func (a ArgsMobSession) QFI() uint8 {
	return a.qfi
}

// R returns the Reflective QoS Indication for this ArgsMobSession.
func (a ArgsMobSession) R() bool {
	return a.r
}

// U returns the U bit for this ArgsMobSession.
func (a ArgsMobSession) U() bool {
	return a.u
}

// PDUSessionID returns the PDU Session Identifier for this ArgsMobSession. The GTP-U equivalent is TEID.
func (a ArgsMobSession) PDUSessionID() uint32 {
	return a.pduSessionID
}

// As5 returns an ArgsMobSession in its 5-byte representation.
func (a ArgsMobSession) As5() [5]byte {
	var b [5]byte
	b[qfiPosByte] |= (qfiMask & a.qfi) << qfiPosBit
	if a.r {
		b[rPosByte] |= rMask << rPosBit
	}
	if a.u {
		b[uPosByte] |= uMask << uPosBit
	}
	binary.BigEndian.PutUint32(b[teidPosByte:teidPosByte+teidSizeByte], a.pduSessionID)
	return b
}

// AsSlice returns an ArgsMobSession in its 5-byte representation.
func (a ArgsMobSession) AsSlice() []byte {
	b := a.As5()
	return b[:]
}

// GoString implements [fmt.GoStringer] interface.
func (a ArgsMobSession) GoString() string {
	return "ArgsMobSession{ QFI: " + strconv.Itoa(int(a.qfi)) +
		", R:" + strconv.FormatBool(a.r) +
		", U:" + strconv.FormatBool(a.u) +
		"PDU Session ID: " + strconv.Itoa(int(a.pduSessionID)) + "}"
}

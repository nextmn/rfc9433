// Copyright 2023 Louis Royer and the NextMN contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT

package encoding

import "encoding/binary"
import "github.com/nextmn/rfc9433/encoding/errors"

const (
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
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|   QFI     |R|U|                PDU Session ID                 |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|PDU Sess(cont')|
//	+-+-+-+-+-+-+-+-+
//	Figure 8: Args.Mob.Session Format
type ArgsMobSession struct {
	qfi          uint8  // QoS Flow Identifier (6 bits)
	r            uint8  // Reflective QoS Indication (1 bit)
	u            uint8  // Unused and for future use (1 bit)
	pduSessionID uint32 // Identifier of PDU Session. The GTP-U equivalent is TEID (32 bits)
}

// NewArgsMobSession creates an ArgsMobSession.
func NewArgsMobSession(qfi uint8, r bool, u bool, pduSessionID uint32) *ArgsMobSession {
	var ruint uint8 = 0
	if r {
		ruint = 1
	}
	var uuint uint8 = 0
	if u {
		uuint = 1
	}
	return &ArgsMobSession{
		qfi:          qfi,
		r:            ruint,
		u:            uuint,
		pduSessionID: pduSessionID,
	}
}

// ParseArgsMobSession parses given byte sequence as an ArgsMobSession.
func ParseArgsMobSession(b []byte) (*ArgsMobSession, error) {
	a := &ArgsMobSession{}
	if err := a.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	return a, nil
}

// QFI returns the Qos Flow Identifier for this ArgsMobSession.
func (a *ArgsMobSession) QFI() uint8 {
	return a.qfi
}

// R returns the Reflective QoS Indication for this ArgsMobSession.
func (a *ArgsMobSession) R() bool {
	if a.r == 0 {
		return false
	}
	return true
}

// U returns the U bit for this ArgsMobSession.
func (a *ArgsMobSession) U() bool {
	if a.u == 0 {
		return false
	}
	return true
}

// PDUSessionID returns the PDU Session Identifier for this ArgsMobSession. The GTP-U equivalent is TEID.
func (a *ArgsMobSession) PDUSessionID() uint32 {
	return a.pduSessionID
}

// MarshalLen returns the serial length of ArgsMobSession.
func (a *ArgsMobSession) MarshalLen() int {
	return 5
}

// Marshal returns the byte sequence generated from ArgsMobSession.
func (a *ArgsMobSession) Marshal() ([]byte, error) {
	b := make([]byte, a.MarshalLen())
	if err := a.MarshalTo(b); err != nil {
		return nil, err
	}
	return b, nil
}

// MarshalTo puts the byte sequence in the byte array given as b.
func (a *ArgsMobSession) MarshalTo(b []byte) error {
	if len(b) < a.MarshalLen() {
		return errors.ErrTooShortToMarshal
	}
	b[qfiPosByte] |= (qfiMask & a.qfi) << qfiPosBit
	b[rPosByte] |= (rMask & a.r) << rPosBit
	b[uPosByte] |= (uMask & a.u) << uPosBit
	binary.BigEndian.PutUint32(b[teidPosByte:teidPosByte+teidSizeByte], a.pduSessionID)
	return nil
}

// UnmarshalBinary sets the values retrieved from byte sequence in an ArgsMobSession.
func (a *ArgsMobSession) UnmarshalBinary(b []byte) error {
	if len(b) < 5 {
		return errors.ErrTooShortToParse
	}
	a.qfi = qfiMask & (b[qfiPosByte] >> qfiPosBit)
	a.r = rMask & (b[rPosByte] >> rPosBit)
	a.u = uMask & (b[uPosByte] >> uPosBit)
	a.pduSessionID = binary.BigEndian.Uint32(b[teidPosByte : teidPosByte+teidSizeByte])
	return nil
}

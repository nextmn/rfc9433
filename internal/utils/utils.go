// Copyright Louis Royer and the NextMN contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT

package utils

// ipv6: Address to extract bits from
// startBit: offset in bits
// length: length of result in Bytes
func FromIPv6(ipv6 [16]byte, startBit int, length int) ([]byte, error) {
	if len(ipv6) < length {
		return nil, ErrOutOfRange
	}
	if startBit+(length*8) > 8*len(ipv6) {
		return nil, ErrOutOfRange
	}
	startByte := startBit / 8
	offset := startBit % 8
	ret := make([]byte, length)
	if offset == 0 {
		copy(ret, ipv6[startByte:startByte+length])
		return ret, nil
	}

	// init left
	for i, b := range ipv6[startByte : startByte+length] {
		ret[i] = (b << offset)
	}
	// init right
	for i, b := range ipv6[startByte+1 : startByte+length+1] {
		ret[i] |= b >> (8 - offset)
	}
	return ret, nil
}

// usage conditions :
// 1. endBit must be positive
// 2. every bit after endBit should be zero (no reset is performed in the function)
func AppendTo16(addr [16]byte, endBit int, appendThis []byte) ([16]byte, error) {
	endByte := endBit / 8
	offset := endBit % 8
	isOffset := 0
	if offset > 0 {
		isOffset = 1
	}
	if isOffset+endByte+len(appendThis) > 16 {
		return [16]byte{}, ErrOutOfRange
	}
	if offset == 0 {
		// concatenate slices
		copy(addr[endByte:], appendThis[:])
		return addr, nil
	}
	//  add right part of bytes
	for i, b := range appendThis {
		addr[endByte+i] |= b >> offset
	}
	// add left part of bytes
	for i, b := range appendThis {
		addr[endByte+isOffset+i] |= b << (8 - offset)
	}
	return addr, nil
}

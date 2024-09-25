// Copyright 2023 Louis Royer and the NextMN contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT

package utils

import "github.com/nextmn/rfc9433/encoding/errors"

// ipv6: Address to extract bits from
// startBit: offset in bits
// length: length of result in Bytes
func FromIPv6(ipv6 [16]byte, startBit uint, length uint) ([]byte, error) {
	if uint(len(ipv6)) < length {
		return nil, errors.ErrTooShortToParse
	}
	if startBit+uint(length*8) > 8*uint(len(ipv6)) {
		return nil, errors.ErrOutOfRange
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
	for i, b := range ipv6[startByte+1 : startByte+length] {
		ret[i] |= b >> (8 - offset)
	}
	return ret, nil
}

// usage conditions :
// 1. slice must be large enough
// 2. every bit after endBit should be zero (no reset is performed in the function)
func AppendToSlice(slice []byte, endBit uint, appendThis []byte) error {
	endByte := endBit / 8
	offset := endBit % 8
	isOffset := 0
	if offset > 0 {
		isOffset = 1
	}
	if isOffset+int(endByte)+len(appendThis) > len(slice) {
		return errors.ErrTooShortToMarshal
	}
	if offset == 0 {
		// concatenate slices
		copy(slice[endByte:], appendThis[:])
		return nil
	}
	//  add right part of bytes
	for i, b := range appendThis {
		slice[int(endByte)+i] |= b >> offset
	}
	// add left part of bytes
	for i, b := range appendThis {
		slice[int(endByte)+isOffset+i] |= b << (8 - offset)
	}
	return nil
}

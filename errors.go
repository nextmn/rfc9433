// Copyright Louis Royer and the NextMN contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT

package rfc9433

import "errors"

var (
	ErrTooShortToMarshal = errors.New("too short to serialize")
	ErrTooShortToParse   = errors.New("too short to parse")
	ErrPrefixLength      = errors.New("wrong prefix length")
)

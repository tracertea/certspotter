// Copyright (C) 2025 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package cttypes

import (
	"fmt"
	"github.com/tracertea/src/certspotter/tlstypes"
	"golang.org/x/crypto/cryptobyte"
)

type SignedCertificateTimestamp struct {
	SCTVersion Version                  `json:"sct_version"`
	ID         LogID                    `json:"id"`
	Timestamp  uint64                   `json:"timestamp"`
	Extensions CTExtensions             `json:"extensions"`
	Signature  tlstypes.DigitallySigned `json:"signature"`
}

func (sct *SignedCertificateTimestamp) Unmarshal(s *cryptobyte.String) error {
	if !sct.SCTVersion.Unmarshal(s) {
		return fmt.Errorf("error reading SCT version")
	}
	if sct.SCTVersion != V1 {
		return fmt.Errorf("unsupported SCT version 0x%02x", sct.SCTVersion)
	}
	if !sct.ID.Unmarshal(s) {
		return fmt.Errorf("error reading SCT id")
	}
	if !s.ReadUint64(&sct.Timestamp) {
		return fmt.Errorf("error reading SCT timestamp")
	}
	if !sct.Extensions.Unmarshal(s) {
		return fmt.Errorf("error reading SCT extensions")
	}
	if !sct.Signature.Unmarshal(s) {
		return fmt.Errorf("error reading SCT signature")
	}
	return nil
}

func ParseSignedCertificateTimestamp(data []byte) (*SignedCertificateTimestamp, error) {
	str := cryptobyte.String(data)
	sct := new(SignedCertificateTimestamp)
	if err := sct.Unmarshal(&str); err != nil {
		return nil, err
	}
	if !str.Empty() {
		return nil, fmt.Errorf("trailing garbage after SignedCertificateTimestamp")
	}
	return sct, nil
}

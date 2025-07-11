// Copyright (C) 2023 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package monitor

import (
	"time"
)

type Config struct {
	LogListSource       string
	State               StateProvider
	StartAtEnd          bool
	Verbose             bool
	HealthCheckInterval time.Duration
	StartIndex          uint64
	EndIndex            uint64
	Proxies             []string
	ResumePoints        map[string]uint64
}

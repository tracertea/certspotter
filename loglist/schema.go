// Copyright (C) 2020 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package loglist

import (
	"strings"
	"time"

	"github.com/tracertea/src/certspotter/cttypes"
)

type List struct {
	Version          string     `json:"version"`
	LogListTimestamp time.Time  `json:"log_list_timestamp"` // Only present in v3 of schema
	Operators        []Operator `json:"operators"`
}

type Operator struct {
	Name      string   `json:"name"`
	Email     []string `json:"email"`
	Logs      []Log    `json:"logs"`
	TiledLogs []Log    `json:"tiled_logs"`
}

type Log struct {
	Key              []byte        `json:"key"`
	LogID            cttypes.LogID `json:"log_id"`
	MMD              int           `json:"mmd"`
	URL              string        `json:"url,omitempty"`            // only for rfc6962 logs
	SubmissionURL    string        `json:"submission_url,omitempty"` // only for static-ct-api logs
	MonitoringURL    string        `json:"monitoring_url,omitempty"` // only for static-ct-api logs
	Description      string        `json:"description"`
	State            State         `json:"state"`
	DNS              string        `json:"dns"`
	LogType          LogType       `json:"log_type"`
	TemporalInterval *struct {
		StartInclusive time.Time `json:"start_inclusive"`
		EndExclusive   time.Time `json:"end_exclusive"`
	} `json:"temporal_interval"`

	// certspotter-specific extensions
	CertspotterDownloadSize int `json:"certspotter_download_size,omitempty"`
	CertspotterDownloadJobs int `json:"certspotter_download_jobs,omitempty"`

	FileName string `json:"-"`

	// TODO: add previous_operators
}

func (log *Log) IsRFC6962() bool     { return log.URL != "" }
func (log *Log) IsStaticCTAPI() bool { return log.SubmissionURL != "" && log.MonitoringURL != "" }

func (log *Log) GetCleanName() string {
	if log.FileName != "" {
		return log.FileName
	}

	logEntryPath := log.URL
	logEntryPath = strings.TrimPrefix(logEntryPath, "https://")
	logEntryPath = strings.TrimPrefix(logEntryPath, "http://")
	logEntryPath = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '_' {
			return r
		}
		if r == ':' || r == '/' {
			return '_'
		}
		return -1 // remove this character
	}, logEntryPath)
	logEntryPath = strings.TrimSuffix(logEntryPath, "_")
	log.FileName = logEntryPath

	return log.FileName
}

// Return URL prefix for submission using the RFC6962 protocol
func (log *Log) GetSubmissionURL() string {
	if log.SubmissionURL != "" {
		return log.SubmissionURL
	} else {
		return log.URL
	}
}

// Return URL prefix for monitoring.
// Since the protocol understood by the URL might be either RFC6962 or static-ct-api, this URL is
// only useful for informational purposes.
func (log *Log) GetMonitoringURL() string {
	if log.MonitoringURL != "" {
		return log.MonitoringURL
	} else {
		return log.URL
	}
}

type State struct {
	Pending *struct {
		Timestamp time.Time `json:"timestamp"`
	} `json:"pending"`

	Qualified *struct {
		Timestamp time.Time `json:"timestamp"`
	} `json:"qualified"`

	Usable *struct {
		Timestamp time.Time `json:"timestamp"`
	} `json:"usable"`

	Readonly *struct {
		Timestamp     time.Time `json:"timestamp"`
		FinalTreeHead struct {
			TreeSize       int64  `json:"tree_size"`
			SHA256RootHash []byte `json:"sha256_root_hash"`
		} `json:"final_tree_head"`
	} `json:"readonly"`

	Retired *struct {
		Timestamp time.Time `json:"timestamp"`
	} `json:"retired"`

	Rejected *struct {
		Timestamp time.Time `json:"timestamp"`
	} `json:"rejected"`
}

func (state *State) IsApproved() bool {
	return state.Qualified != nil || state.Usable != nil || state.Readonly != nil
}

func (state *State) WasApprovedAt(t time.Time) bool {
	return state.Retired != nil && t.Before(state.Retired.Timestamp)
}

type LogType string

const (
	LogTypeProd = "prod"
	LogTypeTest = "test"
)

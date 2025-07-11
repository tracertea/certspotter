// Copyright (C) 2024 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package monitor

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tracertea/src/certspotter/cttypes"
	"github.com/tracertea/src/certspotter/loglist"
	"github.com/tracertea/src/certspotter/merkletree"
)

const keepErrorDays = 7
const errorDateFormat = "2006-01-02"

type FilesystemState struct {
	StateDir          string
	CacheDir          string
	SaveCerts         bool
	Script            string
	ScriptDir         string
	MaxEntriesPerFile uint64
	Stdout            bool
	errorMu           sync.Mutex
}

func (s *FilesystemState) logStateDir(logID LogID) string {
	return filepath.Join(s.StateDir, "logs", logID.Base64URLString())
}

func (s *FilesystemState) Prepare(ctx context.Context) error {
	if err := prepareStateDir(s.StateDir); err != nil {
		return err
	}
	if err := prepareCacheDir(s.CacheDir); err != nil {
		return err
	}
	return nil
}

func (s *FilesystemState) PrepareLog(ctx context.Context, logID LogID) error {
	var (
		stateDirPath        = s.logStateDir(logID)
		sthsDirPath         = filepath.Join(stateDirPath, "unverified_sths")
		malformedDirPath    = filepath.Join(stateDirPath, "malformed_entries")
		healthchecksDirPath = filepath.Join(stateDirPath, "healthchecks")
		errorsDirPath       = filepath.Join(stateDirPath, "errors")
	)
	for _, dirPath := range []string{stateDirPath, sthsDirPath, malformedDirPath, healthchecksDirPath, errorsDirPath} {
		if err := os.Mkdir(dirPath, 0777); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
	}
	return nil
}

func (s *FilesystemState) LoadLogState(ctx context.Context, logID LogID) (*LogState, error) {
	filePath := filepath.Join(s.logStateDir(logID), "state.json")
	fileBytes, err := os.ReadFile(filePath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	state := new(LogState)
	if err := json.Unmarshal(fileBytes, state); err != nil {
		return nil, fmt.Errorf("error parsing %s: %w", filePath, err)
	}
	return state, nil
}

func (s *FilesystemState) StoreLogState(ctx context.Context, logID LogID, state *LogState) error {
	filePath := filepath.Join(s.logStateDir(logID), "state.json")
	return writeJSONFile(filePath, state, 0666)
}

func (s *FilesystemState) StoreSTH(ctx context.Context, logID LogID, sth *cttypes.SignedTreeHead) (*StoredSTH, error) {
	sthsDirPath := filepath.Join(s.logStateDir(logID), "unverified_sths")
	return storeSTHInDir(sthsDirPath, sth)
}

func (s *FilesystemState) LoadSTHs(ctx context.Context, logID LogID) ([]*StoredSTH, error) {
	sthsDirPath := filepath.Join(s.logStateDir(logID), "unverified_sths")
	return loadSTHsFromDir(sthsDirPath)
}

func (s *FilesystemState) RemoveSTH(ctx context.Context, logID LogID, sth *cttypes.SignedTreeHead) error {
	sthsDirPath := filepath.Join(s.logStateDir(logID), "unverified_sths")
	return removeSTHFromDir(sthsDirPath, sth)
}

func (s *FilesystemState) StoreIssuer(ctx context.Context, fingerprint *[32]byte, issuer []byte) error {
	filePath := filepath.Join(s.CacheDir, "issuers", hex.EncodeToString(fingerprint[:]))
	return writeFile(filePath, issuer, 0666)
}

func (s *FilesystemState) LoadIssuer(ctx context.Context, fingerprint *[32]byte) ([]byte, error) {
	filePath := filepath.Join(s.CacheDir, "issuers", hex.EncodeToString(fingerprint[:]))
	issuer, err := os.ReadFile(filePath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	} else {
		return issuer, err
	}
}

// NotifyCert is now a placeholder and is no longer called in the hot path.
// The actual saving logic is in saveCertBatchWorker in monitor.go.
func (s *FilesystemState) NotifyCert(ctx context.Context, cert *DiscoveredCert) error {
	// This function is no longer responsible for saving certificates.
	// That is now handled by the saveCertBatchWorker.
	return nil
}

func (s *FilesystemState) NotifyMalformedEntry(ctx context.Context, entry *LogEntry, parseError error) error {
	var (
		dirPath   = filepath.Join(s.logStateDir(entry.Log.LogID), "malformed_entries")
		entryPath = filepath.Join(dirPath, fmt.Sprintf("%d.json", entry.Index))
		textPath  = filepath.Join(dirPath, fmt.Sprintf("%d.txt", entry.Index))
	)

	summary := fmt.Sprintf("Unable to Parse Entry %d in %s", entry.Index, entry.Log.GetMonitoringURL())
	leafHash := merkletree.HashLeaf(entry.LeafInput())

	text := new(strings.Builder)
	writeField := func(name string, value any) { fmt.Fprintf(text, "\t%13s = %s\n", name, value) }
	fmt.Fprintf(text, "Unable to determine if log entry matches your watchlist. Please file a bug report at https://github.com/SSLMate/certspotter/issues/new with the following details:\n")
	writeField("Log Entry", fmt.Sprintf("%d @ %s", entry.Index, entry.Log.GetMonitoringURL()))
	writeField("Leaf Hash", leafHash.Base64String())
	writeField("Error", parseError.Error())

	if err := writeJSONFile(entryPath, entry.Entry, 0666); err != nil {
		return fmt.Errorf("error saving JSON file: %w", err)
	}
	if err := writeTextFile(textPath, text.String(), 0666); err != nil {
		return fmt.Errorf("error saving texT file: %w", err)
	}

	environ := []string{
		"EVENT=malformed_cert",
		"SUMMARY=" + summary,
		"LOG_URI=" + entry.Log.GetMonitoringURL(),
		"ENTRY_INDEX=" + fmt.Sprint(entry.Index),
		"LEAF_HASH=" + leafHash.Base64String(),
		"PARSE_ERROR=" + parseError.Error(),
		"ENTRY_FILENAME=" + entryPath,
		"TEXT_FILENAME=" + textPath,
		"CERT_PARSEABLE=no", // backwards compat with pre-0.15.0; not documented
	}

	if err := s.notify(ctx, &notification{
		environ: environ,
		summary: summary,
		text:    text.String(),
	}); err != nil {
		return err
	}
	return nil
}

func (s *FilesystemState) healthCheckDir(ctlog *loglist.Log) string {
	if ctlog == nil {
		return filepath.Join(s.StateDir, "healthchecks")
	} else {
		return filepath.Join(s.logStateDir(ctlog.LogID), "healthchecks")
	}
}

func (s *FilesystemState) errorDir(ctlog *loglist.Log) string {
	if ctlog == nil {
		return filepath.Join(s.StateDir, "errors")
	}
	return filepath.Join(s.logStateDir(ctlog.LogID), "errors")
}

func (s *FilesystemState) NotifyHealthCheckFailure(ctx context.Context, ctlog *loglist.Log, info HealthCheckFailure) error {
	textPath := filepath.Join(s.healthCheckDir(ctlog), healthCheckFilename())
	environ := []string{
		"EVENT=error",
		"SUMMARY=" + info.Summary(),
		"TEXT_FILENAME=" + textPath,
	}
	text := info.Text()
	if err := writeTextFile(textPath, text, 0666); err != nil {
		return fmt.Errorf("error saving text file: %w", err)
	}
	if err := s.notify(ctx, &notification{
		environ: environ,
		summary: info.Summary(),
		text:    text,
	}); err != nil {
		return err
	}
	return nil
}

func (s *FilesystemState) NotifyError(ctx context.Context, ctlog *loglist.Log, notifyErr error) error {
	if ctlog == nil {
		log.Print(notifyErr)
	}

	var (
		now      = time.Now()
		filePath = filepath.Join(s.errorDir(ctlog), now.Format(errorDateFormat))
		line     = now.Format(time.RFC3339) + " " + notifyErr.Error() + "\n"
	)

	s.errorMu.Lock()
	defer s.errorMu.Unlock()
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.WriteString(line); err != nil {
		return err
	}
	return file.Close()
}

func (s *FilesystemState) GetErrors(ctx context.Context, ctlog *loglist.Log, count int) (string, error) {
	dir := s.errorDir(ctlog)
	now := time.Now()
	var buf []byte
	for daysBack := 0; count > 0 && daysBack < keepErrorDays; daysBack++ {
		datePath := filepath.Join(dir, now.AddDate(0, 0, -daysBack).Format(errorDateFormat))
		dateBuf, dateLines, err := tailFile(datePath, count)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return "", err
		}
		buf = append(dateBuf, buf...)
		count -= dateLines
	}
	return string(buf), nil
}

func (s *FilesystemState) PruneOldErrors() {
	cutoff := time.Now().AddDate(0, 0, -keepErrorDays)
	pruneDir := func(dir string) {
		entries, err := os.ReadDir(dir)
		if errors.Is(err, fs.ErrNotExist) {
			return
		} else if err != nil {
			log.Printf("unable to read error directory: %s", err)
			return
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			date, err := time.Parse(errorDateFormat, entry.Name())
			if err != nil {
				continue
			}
			if date.Before(cutoff) {
				if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
					log.Printf("unable to remove old error file: %s", err)
				}
			}
		}
	}
	pruneDir(filepath.Join(s.StateDir, "errors"))
	logsDir := filepath.Join(s.StateDir, "logs")
	logDirs, err := os.ReadDir(logsDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Printf("unable to read logs directory: %s", err)
		return
	}
	for _, d := range logDirs {
		if !d.IsDir() {
			continue
		}
		pruneDir(filepath.Join(logsDir, d.Name(), "errors"))
	}
}

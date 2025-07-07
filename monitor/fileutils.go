// Copyright (C) 2017, 2023 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package monitor

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"sync"
)

// fileMutexes holds a mutex for each file being written to, to prevent race conditions.
var fileMutexes = make(map[string]*sync.Mutex)

// mapMutex protects the fileMutexes map itself.
var mapMutex = &sync.Mutex{}

// getFileMutex retrieves or creates a mutex for a specific filename.
// This ensures that all operations on a single file are serialized.
func getFileMutex(filename string) *sync.Mutex {
	mapMutex.Lock()
	defer mapMutex.Unlock()

	if mu, ok := fileMutexes[filename]; ok {
		return mu
	}

	mu := &sync.Mutex{}
	fileMutexes[filename] = mu
	return mu
}

func randomFileSuffix() string {
	var randomBytes [12]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(randomBytes[:])
}

// writeSyncFile opens a file with O_TRUNC, writes data, and syncs to disk.
// This is used for atomic replacement of a file's content.
func writeSyncFile(filename string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err2 := f.Sync(); err2 != nil && err == nil {
		err = err2
	}
	if err2 := f.Close(); err2 != nil && err == nil {
		err = err2
	}
	return err
}

// writeFile atomically writes data to a file by first writing to a temporary file
// and then renaming it. This is NOT concurrency-safe for the same filename
// without external locking.
func writeFile(filename string, data []byte, perm os.FileMode) error {
	tempname := filename + ".tmp." + randomFileSuffix()
	if err := writeSyncFile(tempname, data, perm); err != nil {
		return fmt.Errorf("error writing %s: %w", filename, err)
	}
	if err := os.Rename(tempname, filename); err != nil {
		os.Remove(tempname)
		return fmt.Errorf("error writing %s: %w", filename, err)
	}
	return nil
}

// writeTextFile is a helper to write a string to a file atomically.
func writeTextFile(filename string, fileText string, perm os.FileMode) error {
	return writeFile(filename, []byte(fileText), perm)
}

// writeJSONFile is a helper to marshal a struct to JSON and write it atomically.
func writeJSONFile(filename string, data any, perm os.FileMode) error {
	fileBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}
	fileBytes = append(fileBytes, '\n')
	return writeFile(filename, fileBytes, perm)
}

// --- New Concurrency-Safe Append Functions ---

// appendFile safely appends data to a file. It is concurrency-safe.
// It locks a mutex associated with the filename before performing any operations.
func appendFile(filename string, data []byte, perm os.FileMode) error {
	mu := getFileMutex(filename)
	mu.Lock()
	defer mu.Unlock()

	// Use O_APPEND to add to the end of the file.
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, perm)
	if err != nil {
		return err
	}

	_, err = f.Write(data)
	if err2 := f.Sync(); err2 != nil && err == nil {
		err = err2
	}
	if err2 := f.Close(); err2 != nil && err == nil {
		err = err2
	}
	return err
}

// appendTextFile is a helper to append a string to a file concurrently-safe.
func appendTextFile(filename string, fileText string, perm os.FileMode) error {
	return appendFile(filename, []byte(fileText), perm)
}

// appendJSONFile is a helper to marshal a struct to JSON and append it to a file
// in a concurrency-safe manner.
func appendJSONFile(filename string, data any, perm os.FileMode) error {
	fileBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}
	fileBytes = append(fileBytes, '\n') // Ensure each JSON object is on a new line
	return appendFile(filename, fileBytes, perm)
}

// --- Existing Utility Functions ---

func fileExists(filename string) bool {
	_, err := os.Lstat(filename)
	return err == nil
}

func tailFile(filename string, linesWanted int) ([]byte, int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()
	return tail(file, linesWanted, 4096)
}

func tail(r io.ReadSeeker, linesWanted int, chunkSize int) ([]byte, int, error) {
	var buf []byte
	linesGot := 0

	offset, err := r.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, 0, err
	}
	for offset > 0 {
		readSize := chunkSize
		if offset < int64(readSize) {
			readSize = int(offset)
		}
		offset -= int64(readSize)
		if _, err := r.Seek(offset, io.SeekStart); err != nil {
			return nil, 0, err
		}
		buf = slices.Grow(buf, readSize)
		copy(buf[readSize:len(buf)+readSize], buf)
		buf = buf[:len(buf)+readSize]
		if _, err := io.ReadFull(r, buf[:readSize]); err != nil {
			return nil, 0, err
		}
		for i := readSize; i > 0; i-- {
			if buf[i-1] == '\n' {
				if linesGot == linesWanted {
					return buf[i:], linesGot, nil
				}
				linesGot++
			}
		}
	}
	return buf, linesGot, nil
}

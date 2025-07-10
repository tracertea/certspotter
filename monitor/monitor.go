// Copyright (C) 2025 Opsmate, Inc.
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
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	mathrand "math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/tracertea/src/certspotter/ctclient"
	"github.com/tracertea/src/certspotter/ctcrypto"
	"github.com/tracertea/src/certspotter/cttypes"
	"github.com/tracertea/src/certspotter/loglist"
	"github.com/tracertea/src/certspotter/merkletree"
	"github.com/tracertea/src/certspotter/sequencer"
)

func processRange(ctx context.Context, config *Config) error {
	// Prepare the state directory structure.
	if err := config.State.Prepare(ctx); err != nil {
		return fmt.Errorf("error preparing state directory: %w", err)
	}

	logList, _, err := getLogList(ctx, config.LogListSource, nil)
	if err != nil {
		return fmt.Errorf("error loading log list for range processing: %w", err)
	}

	if len(logList) != 1 {
		return fmt.Errorf("range processing requires a log list with exactly one log, but %d were found", len(logList))
	}

	var ctlog *loglist.Log
	for _, l := range logList {
		ctlog = l // Get the single log from the map
	}

	if config.EndIndex <= config.StartIndex {
		return fmt.Errorf("end-index (%d) must be greater than start-index (%d)", config.EndIndex, config.StartIndex)
	}

	client, issuerGetter, err := newLogClient(config, ctlog)
	if err != nil {
		return err
	}

	// --- Resume Logic ---
	// Create a unique state file name including the scan range to prevent collisions.
	stateFileName := fmt.Sprintf("%s-scan-%d-%d.state", ctlog.LogID.Base64URLString(), config.StartIndex, config.EndIndex)
	stateFilePath := filepath.Join(config.State.(*FilesystemState).StateDir, stateFileName)
	var actualStartIndex uint64

	stateBytes, err := os.ReadFile(stateFilePath)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("could not read resume state file: %w", err)
		}
		actualStartIndex = config.StartIndex
		if config.Verbose {
			log.Printf("Starting new scan for %s from index %d.", ctlog.GetMonitoringURL(), actualStartIndex)
		}
	} else {
		lastProcessedIndex, err := strconv.ParseUint(strings.TrimSpace(string(stateBytes)), 10, 64)
		if err != nil {
			return fmt.Errorf("could not parse resume state file: %w", err)
		}
		actualStartIndex = lastProcessedIndex + 1
		if config.Verbose {
			log.Printf("Resuming scan for %s from index %d.", ctlog.GetMonitoringURL(), actualStartIndex)
		}
	}

	if actualStartIndex >= config.EndIndex {
		log.Println("Scan has already completed or passed the end index. Nothing to do.")
		_ = os.Remove(stateFilePath) // Clean up any lingering state file
		return nil
	}
	// --- End Resume Logic ---

	group, gctx := errgroup.WithContext(ctx)
	batches := make(chan *batch)
	processedBatches := sequencer.New[batch](0, uint64(downloadWorkers(ctlog))*2)
	var batchCounter uint64
	var processWg sync.WaitGroup

	// Batch Generation Worker
	group.Go(func() error {
		defer close(batches)
		for i := actualStartIndex; i < config.EndIndex; i += downloadJobSize(ctlog) {
			end := i + downloadJobSize(ctlog)
			if end > config.EndIndex {
				end = config.EndIndex
			}
			b := &batch{number: batchCounter, begin: i, end: end}
			batchCounter++
			select {
			case <-gctx.Done():
				return gctx.Err()
			case batches <- b:
			}
		}
		return nil
	})

	// Download and Process Workers
	numWorkers := downloadWorkers(ctlog)
	processWg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		group.Go(func() error {
			defer processWg.Done()
			for b := range batches {
				select {
				case <-gctx.Done():
					return gctx.Err()
				default:
				}

				entries, err := getEntriesFull(gctx, client, b.begin, b.end)
				if err != nil {
					return err
				}
				b.entries = entries

				for offset, entry := range b.entries {
					index := b.begin + uint64(offset)
					if err := processLogEntry(gctx, config, issuerGetter, &LogEntry{
						Entry: entry,
						Index: index,
						Log:   ctlog,
					}); err != nil {
						return fmt.Errorf("error processing entry %d: %w", index, err)
					}
				}

				if err := processedBatches.Add(gctx, b.number, b); err != nil {
					return err
				}
			}
			return nil
		})
	}

	// Coordinator to close the sequencer once all processors are done
	group.Go(func() error {
		processWg.Wait()
		processedBatches.Close()
		return nil
	})

	// State Saving Worker
	group.Go(func() error {
		for {
			b, err := processedBatches.Next(gctx)
			if err != nil {
				if errors.Is(err, io.EOF) {
					return nil // All items processed
				}
				return err
			}

			lastProcessed := b.end - 1
			stateContent := strconv.FormatUint(lastProcessed, 10)
			if err := writeTextFile(stateFilePath, stateContent, 0666); err != nil {
				log.Printf("CRITICAL: Failed to save resume state: %v", err)
				return err
			}
			if config.Verbose {
				log.Printf("Progress saved. Last processed index: %d", lastProcessed)
			}
		}
	})

	err = group.Wait()
	if err == nil {
		// Success! Clean up the state file...
		_ = os.Remove(stateFilePath)

		// ...and create the completion receipt.
		completionFileName := fmt.Sprintf("%s-scan-%d-%d.completed", ctlog.LogID.Base64URLString(), config.StartIndex, config.EndIndex)
		completionFilePath := filepath.Join(config.State.(*FilesystemState).StateDir, completionFileName)
		completionContent := fmt.Sprintf(
			"Scan completed successfully.\nTimestamp: %s\nLog: %s\nRange: %d - %d\n",
			time.Now().UTC().Format(time.RFC3339),
			ctlog.GetMonitoringURL(),
			config.StartIndex,
			config.EndIndex,
		)

		if err := writeTextFile(completionFilePath, completionContent, 0666); err != nil {
			// This is not a critical error, but we should log it.
			log.Printf("WARNING: Could not write completion receipt file: %v", err)
		}

		if config.Verbose {
			log.Printf("Scan completed successfully. Removed resume state file and created completion receipt.")
		}
	}
	return err
}

const (
	getSTHInterval    = 5 * time.Minute
	maxPartialTileAge = 5 * time.Minute
)

func downloadJobSize(ctlog *loglist.Log) uint64 {
	if ctlog.IsStaticCTAPI() {
		return ctclient.StaticTileWidth
	} else if ctlog.CertspotterDownloadSize != 0 {
		return uint64(ctlog.CertspotterDownloadSize)
	} else {
		return 1000
	}
}

func downloadWorkers(ctlog *loglist.Log) int {
	if ctlog.CertspotterDownloadJobs != 0 {
		return ctlog.CertspotterDownloadJobs
	} else {
		return 1
	}
}

type verifyEntriesError struct {
	sth             *cttypes.SignedTreeHead
	entriesRootHash merkletree.Hash
}

func (e *verifyEntriesError) Error() string {
	return fmt.Sprintf("error verifying at tree size %d: the STH root hash (%x) does not match the entries returned by the log (%x)", e.sth.TreeSize, e.sth.RootHash, e.entriesRootHash)
}

func withRetry(ctx context.Context, config *Config, ctlog *loglist.Log, maxRetries int, f func() error) error {
	minSleep := 1 * time.Second
	numRetries := 0
	for ctx.Err() == nil {
		err := f()
		if err == nil {
			return nil // Success
		}

		// If the context was canceled, exit immediately.
		if errors.Is(err, context.Canceled) || ctx.Err() != nil {
			return err
		}

		// If the error is "no healthy proxies available", we should log it but not count it as a log-specific error.
		if err.Error() != "no healthy proxies available" {
			recordError(ctx, config, ctlog, err)
		}

		if maxRetries != -1 && numRetries >= maxRetries {
			return fmt.Errorf("%w (retried %d times)", err, numRetries)
		}

		sleepTime := minSleep + mathrand.N(minSleep)
		if err := sleep(ctx, sleepTime); err != nil {
			return err
		}
		minSleep = min(minSleep*2, 1*time.Minute) // Cap the sleep time
		numRetries++
	}
	return ctx.Err()
}

func getEntriesFull(ctx context.Context, client ctclient.Log, startInclusive, endExclusive uint64) ([]ctclient.Entry, error) {
	allEntries := make([]ctclient.Entry, 0, endExclusive-startInclusive)
	for startInclusive < endExclusive {
		entries, err := client.GetEntries(ctx, startInclusive, endExclusive-1)
		if err != nil {
			return nil, err
		}
		allEntries = append(allEntries, entries...)
		startInclusive += uint64(len(entries))
	}
	return allEntries, nil
}

func getAndVerifySTH(ctx context.Context, ctlog *loglist.Log, client ctclient.Log) (*cttypes.SignedTreeHead, string, error) {
	// Add a simple retry loop here for STH fetching, since it's a single request.
	var sth *cttypes.SignedTreeHead
	var url string
	var err error
	for i := 0; i < 5; i++ { // Try up to 5 times
		sth, url, err = client.GetSTH(ctx)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		time.Sleep(time.Duration(i+1) * time.Second)
	}
	if err != nil {
		return nil, "", err
	}

	if err := ctcrypto.PublicKey(ctlog.Key).Verify(ctcrypto.SignatureInputForSTH(sth), sth.Signature); err != nil {
		return nil, "", fmt.Errorf("STH has invalid signature: %w", err)
	}
	return sth, url, nil
}

type logClient struct {
	config *Config
	log    *loglist.Log
	client ctclient.Log
}

func (client *logClient) GetSTH(ctx context.Context) (sth *cttypes.SignedTreeHead, url string, err error) {
	return getAndVerifySTH(ctx, client.log, client.client)
}
func (client *logClient) GetRoots(ctx context.Context) (roots [][]byte, err error) {
	err = withRetry(ctx, client.config, client.log, -1, func() error {
		roots, err = client.client.GetRoots(ctx)
		return err
	})
	return
}

//func (client *logClient) GetEntries(ctx context.Context, startInclusive, endExclusive uint64) (entries []ctclient.Entry, err error) {
//	err = withRetry(ctx, client.config, client.log, -1, func() error {
//		entries, err = client.client.GetEntries(ctx, startInclusive, endExclusive)
//		return err
//	})
//	return
//}
//func (client *logClient) ReconstructTree(ctx context.Context, sth *cttypes.SignedTreeHead) (tree *merkletree.CollapsedTree, err error) {
//	err = withRetry(ctx, client.config, client.log, -1, func() error {
//		tree, err = client.client.ReconstructTree(ctx, sth)
//		return err
//	})
//	return
//}

type issuerGetter struct {
	config    *Config
	log       *loglist.Log
	logGetter ctclient.IssuerGetter
}

func (ig *issuerGetter) GetIssuer(ctx context.Context, fingerprint *[32]byte) ([]byte, error) {
	if issuer, err := ig.config.State.LoadIssuer(ctx, fingerprint); err != nil {
		log.Printf("error loading cached issuer %x (issuer will be retrieved from log instead): %s", *fingerprint, err)
	} else if issuer != nil {
		return issuer, nil
	}

	var issuer []byte
	if err := withRetry(ctx, ig.config, ig.log, 7, func() error {
		var err error
		issuer, err = ig.logGetter.GetIssuer(ctx, fingerprint)
		return err
	}); err != nil {
		return nil, err
	}

	if err := ig.config.State.StoreIssuer(ctx, fingerprint, issuer); err != nil {
		log.Printf("error caching issuer %x (issuer will be re-retrieved from log in the future): %s", *fingerprint, err)
	}

	return issuer, nil
}

func newLogClient(config *Config, ctlog *loglist.Log) (ctclient.Log, ctclient.IssuerGetter, error) {
	switch {
	case ctlog.IsRFC6962():
		logURL, err := url.Parse(ctlog.URL)
		if err != nil {
			return nil, nil, fmt.Errorf("log has invalid URL: %w", err)
		}
		return &logClient{
			config: config,
			log:    ctlog,
			client: &ctclient.RFC6962Log{URL: logURL},
		}, nil, nil
	case ctlog.IsStaticCTAPI():
		submissionURL, err := url.Parse(ctlog.SubmissionURL)
		if err != nil {
			return nil, nil, fmt.Errorf("log has invalid submission URL: %w", err)
		}
		monitoringURL, err := url.Parse(ctlog.MonitoringURL)
		if err != nil {
			return nil, nil, fmt.Errorf("log has invalid monitoring URL: %w", err)
		}
		client := &ctclient.StaticLog{
			SubmissionURL: submissionURL,
			MonitoringURL: monitoringURL,
			ID:            ctlog.LogID,
		}
		return &logClient{
				config: config,
				log:    ctlog,
				client: client,
			}, &issuerGetter{
				config:    config,
				log:       ctlog,
				logGetter: client,
			}, nil
	default:
		return nil, nil, errors.New("log uses unknown protocol")
	}
}

func (client *logClient) GetEntries(ctx context.Context, startInclusive, endInclusive uint64) ([]ctclient.Entry, error) {
	return client.client.GetEntries(ctx, startInclusive, endInclusive)
}
func (client *logClient) ReconstructTree(ctx context.Context, sth *cttypes.SignedTreeHead) (*merkletree.CollapsedTree, error) {
	return client.client.ReconstructTree(ctx, sth)
}

func monitorLogContinously(ctx context.Context, config *Config, ctlog *loglist.Log) (returnedErr error) {
	proxyManager, err := NewProxyManager(ctx, config, ctlog)
	if err != nil {
		return err
	}
	issuerGetter := proxyManager.GetIssuerGetter()

	if err := config.State.PrepareLog(ctx, ctlog.LogID); err != nil {
		return fmt.Errorf("error preparing state: %w", err)
	}
	state, err := config.State.LoadLogState(ctx, ctlog.LogID)
	if err != nil {
		return fmt.Errorf("error loading log state: %w", err)
	}
	if state == nil {
		client, _, err := proxyManager.GetClient()
		if err != nil {
			return fmt.Errorf("failed to get initial client: %w", err)
		}
		if config.StartAtEnd {
			sth, _, err := client.GetSTH(ctx)
			if err != nil {
				return err
			}
			tree, err := client.ReconstructTree(ctx, sth)
			if err != nil {
				return err
			}
			state = &LogState{
				DownloadPosition: tree,
				VerifiedPosition: tree,
				VerifiedSTH:      sth,
				LastSuccess:      time.Now(),
			}
		} else {
			state = &LogState{
				DownloadPosition: merkletree.EmptyCollapsedTree(),
				VerifiedPosition: merkletree.EmptyCollapsedTree(),
				VerifiedSTH:      nil,
				LastSuccess:      time.Now(),
			}
		}
		if config.Verbose {
			log.Printf("%s: monitoring brand new log starting from position %d", ctlog.GetMonitoringURL(), state.DownloadPosition.Size())
		}
		if err := config.State.StoreLogState(ctx, ctlog.LogID, state); err != nil {
			return fmt.Errorf("error storing log state: %w", err)
		}
	} else {
		if config.Verbose {
			log.Printf("%s: resuming monitoring from position %d", ctlog.GetMonitoringURL(), state.DownloadPosition.Size())
		}
	}
	defer func() {
		storeCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := config.State.StoreLogState(storeCtx, ctlog.LogID, state); err != nil && returnedErr == nil {
			returnedErr = fmt.Errorf("error storing log state: %w", err)
		}
	}()

retry:
	position := state.DownloadPosition.Size()

	var latestTreeSize atomic.Uint64
	if state.VerifiedSTH != nil {
		latestTreeSize.Store(state.VerifiedSTH.TreeSize)
	}

	numDownloaders := downloadWorkers(ctlog) * len(proxyManager.proxies)
	if numDownloaders == 0 {
		numDownloaders = 1
	}
	numProcessors := runtime.NumCPU() * 2
	if numProcessors < 4 {
		numProcessors = 4
	}

	if config.Verbose {
		log.Printf(
			"Initializing workers for %s: %d Downloaders, %d Processors",
			ctlog.GetCleanName(), numDownloaders, numProcessors,
		)
	}

	batchesToDownload := make(chan *batch, numDownloaders)
	batchesToProcess := make(chan *batch, numDownloaders)
	processedBatches := sequencer.New[batch](0, uint64(numDownloaders+numProcessors)*10)

	group, gctx := errgroup.WithContext(ctx)

	client, _, err := proxyManager.GetClient()
	if err != nil {
		return fmt.Errorf("no proxies available to start STH worker: %w", err)
	}

	group.Go(func() error { return getSTHAndUpdateWorker(gctx, client, &latestTreeSize) })

	group.Go(func() error {
		defer close(batchesToDownload)
		return generateBatchesWorker(gctx, ctlog, &position, &latestTreeSize, batchesToDownload)
	})

	var downloadWg sync.WaitGroup
	downloadWg.Add(numDownloaders)
	for i := 0; i < numDownloaders; i++ {
		group.Go(func() error {
			defer downloadWg.Done()
			return downloadWorker(gctx, proxyManager, batchesToDownload, batchesToProcess)
		})
	}

	group.Go(func() error {
		downloadWg.Wait()
		close(batchesToProcess)
		return nil
	})

	var processWg sync.WaitGroup
	processWg.Add(numProcessors)
	for i := 0; i < numProcessors; i++ {
		group.Go(func() error {
			defer processWg.Done()
			return processWorker(gctx, config, ctlog, issuerGetter, batchesToProcess, processedBatches)
		})
	}

	group.Go(func() error {
		processWg.Wait()
		processedBatches.Close()
		return nil
	})

	group.Go(func() error {
		return saveStateWorker(gctx, config, ctlog, state, processedBatches, proxyManager)
	})

	err = group.Wait()
	if verifyErr := (*verifyEntriesError)(nil); errors.As(err, &verifyErr) {
		recordError(ctx, config, ctlog, verifyErr)
		state.rewindDownloadPosition()
		if err := config.State.StoreLogState(ctx, ctlog.LogID, state); err != nil {
			return fmt.Errorf("error storing log state: %w", err)
		}
		if err := sleep(ctx, 5*time.Minute); err != nil {
			return err
		}
		goto retry
	}
	return err
}

func newLogClientForProxy(config *Config, ctlog *loglist.Log, proxy string) (ctclient.Log, ctclient.IssuerGetter, error) {
	var httpClient *http.Client
	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid proxy URL %q: %w", proxy, err)
		}
		httpClient = ctclient.NewHTTPClientWithProxy(proxyURL)
	}

	switch {
	case ctlog.IsRFC6962():
		logURL, err := url.Parse(ctlog.URL)
		if err != nil {
			return nil, nil, fmt.Errorf("log has invalid URL: %w", err)
		}
		return &logClient{
			config: config,
			log:    ctlog,
			client: &ctclient.RFC6962Log{URL: logURL, HTTPClient: httpClient},
		}, nil, nil
	case ctlog.IsStaticCTAPI():
		submissionURL, err := url.Parse(ctlog.SubmissionURL)
		if err != nil {
			return nil, nil, fmt.Errorf("log has invalid submission URL: %w", err)
		}
		monitoringURL, err := url.Parse(ctlog.MonitoringURL)
		if err != nil {
			return nil, nil, fmt.Errorf("log has invalid monitoring URL: %w", err)
		}
		client := &ctclient.StaticLog{
			SubmissionURL: submissionURL,
			MonitoringURL: monitoringURL,
			ID:            ctlog.LogID,
			HTTPClient:    httpClient,
		}
		return &logClient{
				config: config,
				log:    ctlog,
				client: client,
			}, &issuerGetter{
				config:    config,
				log:       ctlog,
				logGetter: client,
			}, nil
	default:
		return nil, nil, errors.New("log uses unknown protocol")
	}
}

func getSTHAndUpdateWorker(ctx context.Context, client ctclient.Log, treeSize *atomic.Uint64) error {
	ticker := time.NewTicker(getSTHInterval)
	defer ticker.Stop()

	for {
		// Do one fetch immediately at the start.
		sth, _, err := client.GetSTH(ctx)
		if err != nil {
			// This is a critical failure at the start, so we exit.
			// In a more complex scenario, this could also have its own retry logic.
			return err
		}
		// Atomically update the tree size.
		treeSize.Store(sth.TreeSize)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			// Subsequent fetches happen on the ticker interval.
		}
	}
}

func newLogClients(config *Config, ctlog *loglist.Log) ([]ctclient.Log, ctclient.IssuerGetter, error) {
	if len(config.Proxies) == 0 {
		client, issuerGetter, err := newLogClientForProxy(config, ctlog, "")
		if err != nil {
			return nil, nil, err
		}
		return []ctclient.Log{client}, issuerGetter, nil
	}

	var clients []ctclient.Log
	var firstIssuerGetter ctclient.IssuerGetter
	for _, proxy := range config.Proxies {
		client, issuerGetter, err := newLogClientForProxy(config, ctlog, proxy)
		if err != nil {
			return nil, nil, err
		}
		clients = append(clients, client)
		if firstIssuerGetter == nil {
			firstIssuerGetter = issuerGetter
		}
	}
	return clients, firstIssuerGetter, nil
}

func getSTHWorker(ctx context.Context, config *Config, ctlog *loglist.Log, client ctclient.Log, sthsOut chan<- *cttypes.SignedTreeHead) error {
	ticker := time.NewTicker(getSTHInterval)
	defer ticker.Stop()
	for {
		sth, _, err := client.GetSTH(ctx)
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case sthsOut <- sth:
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

type batch struct {
	number       uint64
	begin, end   uint64
	discoveredAt time.Time        // time at which we became aware of the log having entries in range [begin,end)
	sths         []*StoredSTH     // STHs with sizes in range [begin,end], sorted by TreeSize
	entries      []ctclient.Entry // in range [begin,end)
}

// Create a batch starting from begin, based on sths (which must be non-empty, sorted by TreeSize, and contain only STHs with TreeSize >= begin).  Returns the batch, plus the remaining STHs.
func newBatch(number uint64, begin uint64, sths []*StoredSTH, downloadJobSize uint64) (*batch, []*StoredSTH) {
	batch := &batch{
		number:       number,
		begin:        begin,
		discoveredAt: sths[0].StoredAt,
	}
	maxEnd := (begin/downloadJobSize + 1) * downloadJobSize
	for _, sth := range sths {
		if sth.StoredAt.Before(batch.discoveredAt) {
			batch.discoveredAt = sth.StoredAt
		}
		if sth.TreeSize <= maxEnd {
			batch.end = sth.TreeSize
			batch.sths = append(batch.sths, sth)
		} else {
			batch.end = maxEnd
			break
		}
	}
	return batch, sths[len(batch.sths):]
}

// insert sth into sths, which is sorted by TreeSize, and return a new, still-sorted slice.
// if an equivalent STH is already in sths, it is returned unchanged.
func insertSTH(sths []*StoredSTH, sth *StoredSTH) []*StoredSTH {
	i := len(sths)
	for i > 0 {
		if sths[i-1].Same(&sth.SignedTreeHead) {
			return sths
		}
		if sths[i-1].TreeSize < sth.TreeSize {
			break
		}
		i--
	}
	return slices.Insert(sths, i, sth)
}

func generateBatchesWorker(ctx context.Context, ctlog *loglist.Log, position *uint64, latestTreeSize *atomic.Uint64, batchesOut chan<- *batch) error {
	var batchCounter uint64
	currentPos := *position
	downloadJobSize := downloadJobSize(ctlog)

	// Use a ticker to periodically check for new work, which is cleaner than a hot loop with sleep.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		// Load the latest known size from the STH worker.
		targetSize := latestTreeSize.Load()

		// Generate batches as fast as possible until we catch up to the current target size.
		for currentPos < targetSize {
			end := currentPos + downloadJobSize
			if end > targetSize {
				end = targetSize
			}

			b := &batch{
				number: batchCounter,
				begin:  currentPos,
				end:    end,
			}

			select {
			case <-ctx.Done():
				// If context is canceled, stop everything immediately.
				return ctx.Err()
			case batchesOut <- b:
				// Only advance our position once the batch is accepted by a worker.
				currentPos = end
				batchCounter++
			}
		}

		// Now that we've caught up to the last known size, wait for either
		// the context to be canceled or the ticker to fire for the next check.
		select {
		case <-ctx.Done():
			// This is the graceful exit point. If the context is canceled, we're done.
			return ctx.Err()
		case <-ticker.C:
			// Ticker fired, loop again to check if latestTreeSize has increased.
			continue
		}
	}
}

// downloadWorker is now much smarter. It doesn't requeue work, but instead
// tries to complete its assigned batch using any available healthy proxy.
func downloadWorker(ctx context.Context, pm *ProxyManager, batchesIn <-chan *batch, batchesOut chan<- *batch) error {
	for {
		var batch *batch
		select {
		case <-ctx.Done():
			return ctx.Err()
		case batch = <-batchesIn:
		}

		allEntries := make([]ctclient.Entry, 0, batch.end-batch.begin)
		currentPos := batch.begin

		// This is the new pagination loop.
		for currentPos < batch.end {
			// Fetch one page of entries with robust retry logic.
			pageEntries, err := getEntriesWithRetry(ctx, pm, currentPos, batch.end-1)
			if err != nil {
				// If this fails permanently, the entire log monitoring will stop.
				return err
			}
			allEntries = append(allEntries, pageEntries...)
			currentPos += uint64(len(pageEntries))
		}

		batch.entries = allEntries

		select {
		case <-ctx.Done():
			return ctx.Err()
		case batchesOut <- batch:
		}
	}
}

// getEntriesWithRetry handles the entire lifecycle of fetching a page of entries,
// including handling proxy failures and retries for that specific page.
func getEntriesWithRetry(ctx context.Context, pm *ProxyManager, start, end uint64) ([]ctclient.Entry, error) {
	for {
		// On each attempt, get a new healthy client.
		client, _, err := pm.GetClient()
		if err != nil {
			// All proxies are down, wait before the next attempt.
			if err := sleep(ctx, 10*time.Second); err != nil {
				return nil, err
			}
			continue
		}
		pm.IncrementActive()
		entries, err := client.GetEntries(ctx, start, end)
		pm.AddCertsProcessed(int64(end - start))
		pm.DecrementActive()
		if err == nil {
			pm.ReportSuccess(client)
			return entries, nil
		}

		// Failure, report it. The loop will continue and try another proxy.
		pm.ReportFailure(client)
		recordError(ctx, pm.config, pm.ctlog, err)

		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Brief sleep to prevent a tight loop if all proxies fail quickly.
		if err := sleep(ctx, 1*time.Second); err != nil {
			return nil, err
		}
	}
}

func processWorker(ctx context.Context, config *Config, ctlog *loglist.Log, issuerGetter ctclient.IssuerGetter, batchesIn <-chan *batch, batchesOut *sequencer.Channel[batch]) error {
	for {
		var batch *batch
		select {
		case <-ctx.Done():
			return ctx.Err()
		case batch = <-batchesIn:
		}
		for offset, entry := range batch.entries {
			index := batch.begin + uint64(offset)
			if err := processLogEntry(ctx, config, issuerGetter, &LogEntry{
				Entry: entry,
				Index: index,
				Log:   ctlog,
			}); err != nil {
				return fmt.Errorf("error processing entry %d: %w", index, err)
			}
		}
		if err := batchesOut.Add(ctx, batch.number, batch); err != nil {
			return err
		}
	}
}

func saveStateWorker(ctx context.Context, config *Config, ctlog *loglist.Log, state *LogState, processedBatches *sequencer.Channel[batch], pm *ProxyManager) error {
	logTicker := time.NewTicker(20 * time.Second)
	if !config.Verbose {
		logTicker.Stop()
	} else {
		defer logTicker.Stop()
	}

	for {
		select {
		case <-logTicker.C:
			log.Printf(
				"Log: %s | SaveStateWorker: %d batches pending in sequencer.",
				ctlog.GetCleanName(),
				processedBatches.Len(),
			)
			continue
		default:
		}

		batch, err := processedBatches.Next(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil // Graceful exit
			}
			return err
		}

		// Update throughput counter
		batchSize := batch.end - batch.begin
		pm.AddCertsProcessed(int64(batchSize))

		if batch.begin != state.DownloadPosition.Size() {
			panic(fmt.Errorf("saveStateWorker: expected batch to start at %d but got %d instead", state.DownloadPosition.Size(), batch.begin))
		}
		for {
			for len(batch.sths) > 0 && batch.sths[0].TreeSize == state.DownloadPosition.Size() {
				sth := batch.sths[0]
				batch.sths = batch.sths[1:]
				if rootHash := state.DownloadPosition.CalculateRoot(); sth.RootHash != rootHash {
					return &verifyEntriesError{
						sth:             &sth.SignedTreeHead,
						entriesRootHash: rootHash,
					}
				}
				state.advanceVerifiedPosition()
				state.LastSuccess = sth.StoredAt
				state.VerifiedSTH = &sth.SignedTreeHead
				if err := config.State.StoreLogState(ctx, ctlog.LogID, state); err != nil {
					return fmt.Errorf("error storing log state: %w", err)
				}
				if err := config.State.RemoveSTH(ctx, ctlog.LogID, &sth.SignedTreeHead); err != nil {
					return fmt.Errorf("error removing verified STH: %w", err)
				}
				if config.Verbose {
					log.Printf("%s: verified position is now %d", ctlog.GetMonitoringURL(), sth.SignedTreeHead.TreeSize)
				}
			}
			if len(batch.entries) == 0 {
				break
			}
			entry := batch.entries[0]
			batch.entries = batch.entries[1:]
			leafHash := merkletree.HashLeaf(entry.LeafInput())
			state.DownloadPosition.Add(leafHash)
		}

		if err := config.State.StoreLogState(ctx, ctlog.LogID, state); err != nil {
			return fmt.Errorf("error storing log state: %w", err)
		}
	}
}

func sleep(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

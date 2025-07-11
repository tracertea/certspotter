// Copyright (C) 2016, 2023 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/tracertea/src/certspotter/ctclient"
	"github.com/tracertea/src/certspotter/loglist"
	"github.com/tracertea/src/certspotter/monitor"
)

var programName = os.Args[0]
var Version = "unknown"
var Source = "unknown"

const defaultLogList = "https://loglist.certspotter.org/monitor.json"

func certspotterVersion() (string, string) {
	if buildinfo, ok := debug.ReadBuildInfo(); ok && strings.HasPrefix(buildinfo.Main.Version, "v") {
		return strings.TrimPrefix(buildinfo.Main.Version, "v"), buildinfo.Main.Path
	} else {
		return Version, Source
	}
}

func fileExists(filename string) bool {
	_, err := os.Lstat(filename)
	return err == nil
}
func homedir() string {
	homedir, err := os.UserHomeDir()
	if err != nil {
		panic(fmt.Errorf("unable to determine home directory: %w", err))
	}
	return homedir
}
func defaultStateDir() string {
	if envVar := os.Getenv("CERTSPOTTER_STATE_DIR"); envVar != "" {
		return envVar
	} else {
		return filepath.Join(homedir(), ".certspotter")
	}
}
func defaultConfigDir() string {
	if envVar := os.Getenv("CERTSPOTTER_CONFIG_DIR"); envVar != "" {
		return envVar
	} else {
		return filepath.Join(homedir(), ".certspotter")
	}
}
func defaultCacheDir() string {
	userCacheDir, err := os.UserCacheDir()
	if err != nil {
		panic(fmt.Errorf("unable to determine user cache directory: %w", err))
	}
	return filepath.Join(userCacheDir, "certspotter")
}
func defaultWatchListPath() string {
	return filepath.Join(defaultConfigDir(), "watchlist")
}
func defaultWatchListPathIfExists() string {
	if fileExists(defaultWatchListPath()) {
		return defaultWatchListPath()
	} else {
		return ""
	}
}
func defaultScriptDir() string {
	return filepath.Join(defaultConfigDir(), "hooks.d")
}
func defaultEmailFile() string {
	return filepath.Join(defaultConfigDir(), "email_recipients")
}

func simplifyError(err error) error {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err
	}

	return err
}

func readWatchListFile(filename string) (monitor.WatchList, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, simplifyError(err)
	}
	defer file.Close()
	return monitor.ReadWatchList(file)
}

func readEmailFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, simplifyError(err)
	}
	defer file.Close()

	var emails []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		emails = append(emails, line)
	}
	return emails, err
}

func appendFunc(slice *[]string) func(string) error {
	return func(value string) error {
		*slice = append(*slice, value)
		return nil
	}
}

func main() {
	version, source := certspotterVersion()

	ctclient.UserAgent = fmt.Sprintf("certspotter/%s (%s; %s; %s; %s; +https://github.com/SSLMate/certspotter)", version, source, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	loglist.UserAgent = ctclient.UserAgent

	var flags struct {
		batchSize         bool
		healthcheck       time.Duration
		logs              string
		noSave            bool
		script            string
		startAtEnd        bool
		stateDir          string
		maxEntriesPerFile uint64
		stdout            bool
		verbose           bool
		version           bool
		startIndex        uint64
		endIndex          uint64
		localAddr         string
		proxies           []string
		resumeFromFile    string
	}
	flag.Func("batch_size", "Obsolete; do not use", func(string) error { flags.batchSize = true; return nil }) // TODO: remove in 0.21.0
	flag.DurationVar(&flags.healthcheck, "healthcheck", 24*time.Hour, "How frequently to perform a health check")
	flag.StringVar(&flags.logs, "logs", defaultLogList, "File path or URL of JSON list of logs to monitor")
	flag.BoolVar(&flags.noSave, "no_save", false, "Do not save a copy of matching certificates in state directory")
	flag.Func("proxy", "Proxy to use for HTTP requests (repeatable). E.g. http://user:pass@host:port", appendFunc(&flags.proxies))
	flag.StringVar(&flags.script, "script", "", "Program to execute when a matching certificate is discovered")
	flag.BoolVar(&flags.startAtEnd, "start_at_end", false, "Start monitoring new logs from the end rather than the beginning (saves considerable bandwidth)")
	flag.StringVar(&flags.stateDir, "state_dir", defaultStateDir(), "Directory for storing log position and discovered certificates")
	flag.Uint64Var(&flags.maxEntriesPerFile, "max_entries_per_file", 100000, "Maximum number of entries to store in a single file in the state directory (default: 100000)")
	flag.BoolVar(&flags.stdout, "stdout", false, "Write matching certificates to stdout")
	flag.BoolVar(&flags.verbose, "verbose", false, "Print detailed information about certspotter's operation to stderr")
	flag.BoolVar(&flags.version, "version", false, "Print version and exit")
	flag.Uint64Var(&flags.startIndex, "start-index", 0, "Log index to start processing from (requires -end-index).")
	flag.Uint64Var(&flags.endIndex, "end-index", 0, "Log index to end processing at (requires -start-index).")
	flag.StringVar(&flags.localAddr, "local-addr", "", "Local IP address to use for outbound connections.")
	flag.StringVar(&flags.resumeFromFile, "resume-from-file", "", "Path to a JSON file specifying starting indices for individual logs.")
	flag.Parse()

	if flags.batchSize {
		fmt.Fprintf(os.Stderr, "%s: -batch_size is obsolete; please remove it from your command line\n", programName)
		os.Exit(2)
	}
	if flags.version {
		fmt.Fprintf(os.Stdout, "certspotter version %s (%s)\n", version, source)
		os.Exit(0)
	}

	if (flags.startIndex > 0 || flags.endIndex > 0) && (flags.startIndex >= flags.endIndex) {
		fmt.Fprintf(os.Stderr, "%s: -start-index and -end-index must be used together\n", programName)
		os.Exit(2)
	}

	if flags.localAddr != "" {
		customDialContext := func(ctx context.Context, network, address string) (net.Conn, error) {
			localTCPAddr, err := net.ResolveTCPAddr(network, flags.localAddr+":0")
			if err != nil {
				return nil, fmt.Errorf("failed to resolve local address %s: %w", flags.localAddr, err)
			}

			d := &net.Dialer{
				LocalAddr: localTCPAddr,
			}
			return d.DialContext(ctx, network, address)
		}

		customClient := ctclient.NewDialHTTPClient(customDialContext)
		ctclient.SetDefaultHTTPClient(customClient)
	}

	fsstate := &monitor.FilesystemState{
		StateDir:          flags.stateDir,
		CacheDir:          defaultCacheDir(),
		SaveCerts:         !flags.noSave,
		Script:            flags.script,
		ScriptDir:         defaultScriptDir(),
		Stdout:            flags.stdout,
		MaxEntriesPerFile: flags.maxEntriesPerFile,
	}
	config := &monitor.Config{
		LogListSource:       flags.logs,
		State:               fsstate,
		StartAtEnd:          flags.startAtEnd,
		Verbose:             flags.verbose,
		HealthCheckInterval: flags.healthcheck,
		Proxies:             flags.proxies,
		StartIndex:          flags.startIndex,
		EndIndex:            flags.endIndex,
	}

	if flags.resumeFromFile != "" {
		data, err := os.ReadFile(flags.resumeFromFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: could not read resume file: %v\n", programName, err)
			os.Exit(1)
		}
		if err := json.Unmarshal(data, &config.ResumePoints); err != nil {
			fmt.Fprintf(os.Stderr, "%s: could not parse resume file: %v\n", programName, err)
			os.Exit(1)
		}
	}

	if fsstate.Script == "" && !fileExists(fsstate.ScriptDir) && fsstate.Stdout == false {
		fmt.Fprintf(os.Stderr, "%s: no notification methods were specified\n", programName)
		fmt.Fprintf(os.Stderr, "Please specify at least one of the following notification methods:\n")
		fmt.Fprintf(os.Stderr, " - Place one or more email addresses in %s (one address per line)\n", defaultEmailFile())
		fmt.Fprintf(os.Stderr, " - Place one or more executable scripts in the %s directory\n", fsstate.ScriptDir)
		fmt.Fprintf(os.Stderr, " - Specify an email address using the -email flag\n")
		fmt.Fprintf(os.Stderr, " - Specify the path to an executable script using the -script flag\n")
		fmt.Fprintf(os.Stderr, " - Specify the -stdout flag\n")
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			fsstate.PruneOldErrors()
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()

	if err := monitor.Run(ctx, config); ctx.Err() == context.Canceled && errors.Is(err, context.Canceled) {
		if flags.verbose {
			fmt.Fprintf(os.Stderr, "%s: exiting due to SIGINT or SIGTERM\n", programName)
		}
		os.Exit(0)
	} else {
		fmt.Fprintf(os.Stderr, "%s: %s\n", programName, err)
		os.Exit(1)
	}
}

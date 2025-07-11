// Copyright (C) 2025 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

// Package ctclient implements a client for monitoring RFC6962 and static-ct-api Certificate Transparency logs
package ctclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

var UserAgent = ""

// HTTPError is returned by `get` when the HTTP status is not 200 OK.
type HTTPError struct {
	Status     string
	StatusCode int
	URL        string
	Body       []byte
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("Get %q: %s (%q)", e.URL, e.Status, bytes.TrimSpace(e.Body))
}

// NewHTTPClient creates an HTTP client suitable for communicating with CT logs using the default environment proxy settings.
func NewHTTPClient() *http.Client {
	return NewHTTPClientWithProxy(nil)
}

// NewHTTPClientWithProxy creates an HTTP client suitable for communicating with CT logs via a specific proxy.
// If proxyURL is nil, http.ProxyFromEnvironment is used.
func NewHTTPClientWithProxy(proxyURL *url.URL) *http.Client {
	proxyFunc := http.ProxyFromEnvironment
	if proxyURL != nil {
		proxyFunc = http.ProxyURL(proxyURL)
	}

	return &http.Client{
		Transport: &http.Transport{
			Proxy: proxyFunc,
			// Set a specific Dial timeout to fail faster on dead hosts
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			ForceAttemptHTTP2: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirects not followed")
		},
		Timeout: 60 * time.Second, // Overall request timeout
	}
}

// Create an HTTP client suitable for communicating with CT logs.  dialContext, if non-nil, is used for dialing.
func NewDialHTTPClient(dialContext func(context.Context, string, string) (net.Conn, error)) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig: &tls.Config{
				// We have to disable TLS certificate validation because several logs
				// (WoSign, StartCom, GDCA) use certificates that are not widely trusted.
				// Since we verify that every response we receive from the log is signed
				// by the log's CT public key (either directly, or indirectly via the Merkle Tree),
				// TLS certificate validation is not actually necessary.  (We don't want to manage
				// our own trust store because that adds undesired complexity and would require
				// updating should a log ever change to a different CA.)
				InsecureSkipVerify: true,
			},
			DialContext:       dialContext,
			ForceAttemptHTTP2: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirects not followed")
		},
		Timeout: 60 * time.Second,
	}
}

var defaultHTTPClient = NewHTTPClient()

func SetDefaultHTTPClient(client *http.Client) {
	defaultHTTPClient = client
}

func get(ctx context.Context, httpClient *http.Client, fullURL string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", UserAgent)

	if httpClient == nil {
		httpClient = defaultHTTPClient
	}

	response, err := httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		return nil, &HTTPError{
			Status:     response.Status,
			StatusCode: response.StatusCode,
			URL:        fullURL,
			Body:       body,
		}
	}

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("Get %q: error reading response: %w", fullURL, err)
	}

	return responseBody, nil
}

func getJSON(ctx context.Context, httpClient *http.Client, fullURL string, response any) error {
	responseBytes, err := get(ctx, httpClient, fullURL)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(responseBytes, response); err != nil {
		return fmt.Errorf("Get %q: error parsing response JSON: %w", fullURL, err)
	}
	return nil
}

func getRoots(ctx context.Context, httpClient *http.Client, logURL *url.URL) ([][]byte, error) {
	fullURL := logURL.JoinPath("/ct/v1/get-roots").String()
	var parsedResponse struct {
		Certificates [][]byte `json:"certificates"`
	}
	if err := getJSON(ctx, httpClient, fullURL, &parsedResponse); err != nil {
		return nil, err
	}
	return parsedResponse.Certificates, nil
}

// monitor/proxy_manager.go
package monitor

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tracertea/src/certspotter/ctclient"
	"github.com/tracertea/src/certspotter/loglist"
)

const (
	failureThreshold      = 3
	cooldownDuration      = 5 * time.Minute
	probeInterval         = 1 * time.Minute
	statusLogInterval     = 1 * time.Minute // New constant for status logging
	throughputLogInterval = 1 * time.Minute
)

type proxyState struct {
	client        ctclient.Log
	address       string // For logging
	failures      int
	isUnhealthy   bool
	cooldownUntil time.Time
}

// ProxyManager manages a pool of proxy clients, tracking their health
// and implementing a circuit breaker pattern.
type ProxyManager struct {
	mu             sync.Mutex
	proxies        []*proxyState
	next           int // for round-robin
	config         *Config
	ctlog          *loglist.Log
	issuerGetter   ctclient.IssuerGetter // The issuer getter is the same for all proxies of a log
	activeRequests atomic.Int64
	certsProcessed atomic.Int64
}

// NewProxyManager creates a manager for a set of proxies.
func NewProxyManager(ctx context.Context, config *Config, ctlog *loglist.Log) (*ProxyManager, error) {
	pm := &ProxyManager{
		config: config,
		ctlog:  ctlog,
	}

	proxies := config.Proxies
	if len(proxies) == 0 {
		proxies = []string{""} // Add an empty proxy for direct connection
	}

	for _, proxyAddr := range proxies {
		var proxyURL *url.URL
		if proxyAddr != "" {
			var err error
			proxyURL, err = url.Parse(proxyAddr)
			if err != nil {
				return nil, fmt.Errorf("invalid proxy url %q: %w", proxyAddr, err)
			}
		}

		httpClient := ctclient.NewHTTPClientWithProxy(proxyURL)

		var client ctclient.Log
		var currentIssuerGetter ctclient.IssuerGetter

		switch {
		case ctlog.IsRFC6962():
			logURL, err := url.Parse(ctlog.URL)
			if err != nil {
				return nil, fmt.Errorf("log has invalid URL: %w", err)
			}
			client = &ctclient.RFC6962Log{URL: logURL, HTTPClient: httpClient}
		case ctlog.IsStaticCTAPI():
			submissionURL, _ := url.Parse(ctlog.SubmissionURL)
			monitoringURL, _ := url.Parse(ctlog.MonitoringURL)
			staticClient := &ctclient.StaticLog{
				SubmissionURL: submissionURL,
				MonitoringURL: monitoringURL,
				ID:            ctlog.LogID,
				HTTPClient:    httpClient,
			}
			client = staticClient
			currentIssuerGetter = &issuerGetter{
				config:    config,
				log:       ctlog,
				logGetter: staticClient,
			}
		default:
			return nil, errors.New("log uses unknown protocol")
		}

		addrForLog := "direct"
		if proxyAddr != "" {
			addrForLog = proxyAddr
		}

		pm.proxies = append(pm.proxies, &proxyState{
			client:  &logClient{config: config, log: ctlog, client: client},
			address: addrForLog,
		})

		// All proxies for a log share the same issuerGetter logic, so we only need to set it once.
		if pm.issuerGetter == nil {
			pm.issuerGetter = currentIssuerGetter
		}
	}
	if config.Verbose {
		log.Printf("ProxyManager for %s initialized with %d proxies.", ctlog.GetMonitoringURL(), len(pm.proxies))
	}

	go pm.startProbing(ctx)
	go pm.startStatusLogger(ctx) // Start the new status logger
	go pm.startThroughputLogger(ctx)

	return pm, nil
}

// ADDED: New function to periodically log throughput.
func (pm *ProxyManager) startThroughputLogger(ctx context.Context) {
	if !pm.config.Verbose {
		return
	}

	ticker := time.NewTicker(throughputLogInterval)
	defer ticker.Stop()

	var lastCount int64
	var lastTime time.Time

	for {
		select {
		case <-ctx.Done():
			return
		case t := <-ticker.C:
			currentCount := pm.certsProcessed.Load()

			// Don't log on the first tick, just capture the initial state.
			if !lastTime.IsZero() {
				elapsed := t.Sub(lastTime).Seconds()
				processedInInterval := currentCount - lastCount

				// Avoid division by zero if the interval is super short
				if elapsed > 0 {
					rate := float64(processedInInterval) / elapsed
					log.Printf(
						"Throughput for %s -> Rate: %.2f certs/sec (Processed %d in last %.fs)",
						pm.ctlog.GetMonitoringURL(),
						rate,
						processedInInterval,
						elapsed,
					)
				}
			}

			// Update state for the next interval.
			lastCount = currentCount
			lastTime = t
		}
	}
}

// Method to increment the active request counter.
func (pm *ProxyManager) IncrementActive() {
	pm.activeRequests.Add(1)
}

// Method to decrement the active request counter.
func (pm *ProxyManager) DecrementActive() {
	pm.activeRequests.Add(-1)
}

// ADDED: New method to add a number of processed certs to the counter.
func (pm *ProxyManager) AddCertsProcessed(count int64) {
	pm.certsProcessed.Add(count)
}

// GetClient returns a healthy client from the pool using round-robin.
// If all proxies are unhealthy, it returns an error.
func (pm *ProxyManager) GetClient() (ctclient.Log, string, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for i := 0; i < len(pm.proxies); i++ {
		// Round-robin to find the next healthy proxy
		idx := (pm.next + i) % len(pm.proxies)
		proxy := pm.proxies[idx]

		if !proxy.isUnhealthy {
			pm.next = (idx + 1) % len(pm.proxies)
			//if pm.config.Verbose {
			//	log.Printf("ProxyManager for %s: providing client for proxy %s", pm.ctlog.GetMonitoringURL(), proxy.address)
			//}
			return proxy.client, proxy.address, nil
		}
	}
	if pm.config.Verbose {
		log.Printf("ProxyManager for %s: no healthy proxies available.", pm.ctlog.GetMonitoringURL())
	}
	return nil, "", errors.New("no healthy proxies available")
}

// GetIssuerGetter returns the issuer getter for this log type.
func (pm *ProxyManager) GetIssuerGetter() ctclient.IssuerGetter {
	return pm.issuerGetter
}

// ReportFailure is called by a worker when a request fails.
func (pm *ProxyManager) ReportFailure(failedClient ctclient.Log) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for _, p := range pm.proxies {
		if p.client == failedClient {
			// If the proxy is already marked unhealthy, this failure is from an
			// in-flight request that started before the circuit was tripped.
			// We can log it but don't need to increment the failure count.
			if p.isUnhealthy {
				if pm.config.Verbose {
					log.Printf("ProxyManager for %s: received failure report for already unhealthy proxy %s (in-flight request). Ignoring.", pm.ctlog.GetMonitoringURL(), p.address)
				}
				return
			}

			p.failures++
			if pm.config.Verbose {
				log.Printf("ProxyManager for %s: failure reported for proxy %s. Failure count: %d/%d", pm.ctlog.GetMonitoringURL(), p.address, p.failures, failureThreshold)
			}
			if p.failures >= failureThreshold {
				p.isUnhealthy = true
				p.cooldownUntil = time.Now().Add(cooldownDuration)
				if pm.config.Verbose {
					log.Printf("ProxyManager for %s: proxy %s marked as UNHEALTHY. Cooling down until %s.", pm.ctlog.GetMonitoringURL(), p.address, p.cooldownUntil.Format(time.RFC3339))
				}
			}
			return
		}
	}
}

// ReportSuccess is called by a worker when a request succeeds.
func (pm *ProxyManager) ReportSuccess(succeededClient ctclient.Log) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for _, p := range pm.proxies {
		if p.client == succeededClient {
			if p.failures > 0 {
				if pm.config.Verbose {
					log.Printf("ProxyManager for %s: success reported for proxy %s. Resetting failure count.", pm.ctlog.GetMonitoringURL(), p.address)
				}
				p.failures = 0
			}
			if p.isUnhealthy {
				if pm.config.Verbose {
					log.Printf("ProxyManager for %s: proxy %s marked as HEALTHY again.", pm.ctlog.GetMonitoringURL(), p.address)
				}
				p.isUnhealthy = false
			}
			return
		}
	}
}

// startProbing periodically checks unhealthy proxies to see if they've recovered.
func (pm *ProxyManager) startProbing(ctx context.Context) {
	if pm.config.Verbose {
		log.Printf("ProxyManager for %s: starting probe worker.", pm.ctlog.GetMonitoringURL())
	}
	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pm.mu.Lock()
			for _, p := range pm.proxies {
				if p.isUnhealthy && time.Now().After(p.cooldownUntil) {
					if pm.config.Verbose {
						log.Printf("ProxyManager for %s: probing proxy %s (cooldown finished). Moving to half-open state.", pm.ctlog.GetMonitoringURL(), p.address)
					}
					// This is the half-open state. We mark it as healthy
					// so a worker can try it. If it fails, ReportFailure
					// will mark it unhealthy again. If it succeeds, ReportSuccess
					// will confirm it's healthy.
					p.isUnhealthy = false
					p.failures = 0
				}
			}
			pm.mu.Unlock()
		}
	}
}

// logStatus prints a summary of the current state of all proxies.
func (pm *ProxyManager) logStatus() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	var statusStrings []string
	for _, p := range pm.proxies {
		status := "HEALTHY"
		if p.isUnhealthy {
			status = fmt.Sprintf("UNHEALTHY (cooldown until %s)", p.cooldownUntil.Format(time.Kitchen))
		}
		statusStrings = append(statusStrings, fmt.Sprintf("%s: %s, failures: %d/%d", p.address, status, p.failures, failureThreshold))
	}
	activeCount := pm.activeRequests.Load()
	log.Printf(
		"Proxy status for %s -> Active Requests: %d | [ %s ]",
		pm.ctlog.GetMonitoringURL(),
		activeCount,
		strings.Join(statusStrings, " | "),
	)
}

// startStatusLogger runs a loop to periodically log the proxy statuses.
func (pm *ProxyManager) startStatusLogger(ctx context.Context) {
	// Don't log status if not in verbose mode.
	if !pm.config.Verbose {
		return
	}

	ticker := time.NewTicker(statusLogInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pm.logStatus()
		}
	}
}

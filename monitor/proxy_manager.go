// monitor/proxy_manager.go
package monitor

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"reflect"
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
	statusLogInterval     = 1 * time.Minute
	throughputLogInterval = 1 * time.Minute
	maxResponseTimes      = 100
	rateLimitWindow       = 5 * time.Minute
	defaultSlotsPerProxy  = 4
)

type proxyState struct {
	client             ctclient.Log
	address            string
	isUnhealthy        bool
	cooldownUntil      time.Time
	failures           int
	requestsCompleted  atomic.Int64
	lastLoggedRequests int64
	// Metrics
	responseTimes   []time.Duration
	responseTimesMu sync.Mutex
	recent429s      []time.Time
	recent429sMu    sync.Mutex
	// Concurrency control
	requestSlots chan struct{}
}

// ProxyManager manages a pool of proxy clients, tracking their health
// and implementing adaptive concurrency limiting.
type ProxyManager struct {
	mu             sync.Mutex
	proxies        []*proxyState
	issuerGetter   ctclient.IssuerGetter
	config         *Config
	ctlog          *loglist.Log
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
		proxies = []string{""} // Direct connection
	}

	slotsCount := defaultSlotsPerProxy
	if ctlog.CertspotterDownloadJobs > 0 {
		slotsCount = ctlog.CertspotterDownloadJobs
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
				return nil, fmt.Errorf("invalid log URL: %w", err)
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

		slots := make(chan struct{}, slotsCount)
		for i := 0; i < slotsCount; i++ {
			slots <- struct{}{}
		}

		pm.proxies = append(pm.proxies, &proxyState{
			client:       &logClient{config: config, log: ctlog, client: client},
			address:      addrForLog,
			requestSlots: slots,
		})

		if pm.issuerGetter == nil {
			pm.issuerGetter = currentIssuerGetter
		}
	}

	if config.Verbose {
		log.Printf("ProxyManager for %s initialized with %d proxies, each with %d slots.", ctlog.GetMonitoringURL(), len(pm.proxies), slotsCount)
	}

	go pm.startProbing(ctx)
	go pm.startStatusLogger(ctx)
	go pm.startThroughputLogger(ctx)

	return pm, nil
}

func (p *proxyState) rollingAverage() time.Duration {
	p.responseTimesMu.Lock()
	defer p.responseTimesMu.Unlock()
	if len(p.responseTimes) == 0 {
		return 0
	}
	var sum time.Duration
	for _, d := range p.responseTimes {
		sum += d
	}
	return sum / time.Duration(len(p.responseTimes))
}

func (p *proxyState) count429s(interval time.Duration) int {
	p.recent429sMu.Lock()
	defer p.recent429sMu.Unlock()
	cutoff := time.Now().Add(-interval)
	n := 0
	for i, t := range p.recent429s {
		if t.After(cutoff) {
			p.recent429s[n] = p.recent429s[i]
			n++
		}
	}
	p.recent429s = p.recent429s[:n]
	return n
}

// GetClient blocks until a request slot is available from any healthy proxy.
// It returns the client to use. The caller MUST call ReleaseClient when done.
func (pm *ProxyManager) GetClient(ctx context.Context) (ctclient.Log, error) {
	pm.mu.Lock()
	cases := []reflect.SelectCase{{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(ctx.Done())}}
	proxyMap := make(map[int]*proxyState)

	for _, p := range pm.proxies {
		if !p.isUnhealthy {
			cases = append(cases, reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(p.requestSlots)})
			proxyMap[len(cases)-1] = p
		}
	}
	pm.mu.Unlock()

	if len(proxyMap) == 0 {
		if pm.config.Verbose {
			log.Printf("ProxyManager for %s: All proxies are unhealthy. Waiting for recovery.", pm.ctlog.GetMonitoringURL())
		}
		select {
		case <-time.After(probeInterval):
			return pm.GetClient(ctx)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	chosen, _, _ := reflect.Select(cases)

	if chosen == 0 { // Context was canceled
		return nil, ctx.Err()
	}

	proxy := proxyMap[chosen]
	return proxy.client, nil
}

// ReleaseClient returns a request slot to the proxy it came from and reports success or failure.
// Pass a non-nil duration on success, or nil on failure.
func (pm *ProxyManager) ReleaseClient(client ctclient.Log, duration *time.Duration) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for _, p := range pm.proxies {
		if p.client == client {
			p.requestSlots <- struct{}{}

			if duration != nil { // Success case
				p.requestsCompleted.Add(1)
				if p.failures > 0 {
					p.failures = 0
				}
				if p.isUnhealthy {
					if pm.config.Verbose {
						log.Printf("ProxyManager for %s: proxy %s marked as HEALTHY again.", pm.ctlog.GetMonitoringURL(), p.address)
					}
					p.isUnhealthy = false
				}
				p.responseTimesMu.Lock()
				p.responseTimes = append(p.responseTimes, *duration)
				if len(p.responseTimes) > maxResponseTimes {
					p.responseTimes = p.responseTimes[1:]
				}
				p.responseTimesMu.Unlock()
			} else { // Failure case
				if p.isUnhealthy {
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
			}
			return
		}
	}
}

func (pm *ProxyManager) startProbing(ctx context.Context) {
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
						log.Printf("ProxyManager for %s: probing proxy %s. Moving to half-open state.", pm.ctlog.GetMonitoringURL(), p.address)
					}
					p.isUnhealthy = false
					p.failures = 0
				}
			}
			pm.mu.Unlock()
		}
	}
}

func (pm *ProxyManager) logStatus() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	var statusStrings []string
	for _, p := range pm.proxies {
		status := "HEALTHY"
		if p.isUnhealthy {
			status = fmt.Sprintf("UNHEALTHY (cooldown until %s)", p.cooldownUntil.Format(time.Kitchen))
		}

		slotsCapacity := cap(p.requestSlots)
		usedSlots := slotsCapacity - len(p.requestSlots)

		currentRequests := p.requestsCompleted.Load()
		requestsSinceLast := currentRequests - p.lastLoggedRequests
		p.lastLoggedRequests = currentRequests

		statusStrings = append(statusStrings, fmt.Sprintf("%s: %s, fails: %d/%d, slots: %d/%d, avg_resp: %v, 429s(5m): %d, reqs: %d", p.address, status, p.failures, failureThreshold, usedSlots, slotsCapacity, p.rollingAverage().Round(time.Millisecond), p.count429s(rateLimitWindow), requestsSinceLast))
	}
	log.Printf(
		"Proxy status for %s -> [ %s ]",
		pm.ctlog.GetMonitoringURL(),
		strings.Join(statusStrings, " | "),
	)
}

func (pm *ProxyManager) startStatusLogger(ctx context.Context) {
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

func (pm *ProxyManager) AddCertsProcessed(count int64) {
	pm.certsProcessed.Add(count)
}

func (pm *ProxyManager) GetIssuerGetter() ctclient.IssuerGetter {
	return pm.issuerGetter
}

func (pm *ProxyManager) startThroughputLogger(ctx context.Context) {
	if !pm.config.Verbose {
		return
	}
	ticker := time.NewTicker(throughputLogInterval)
	defer ticker.Stop()
	var lastCount int64
	lastTime := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case t := <-ticker.C:
			currentCount := pm.certsProcessed.Load()
			elapsed := t.Sub(lastTime).Seconds()
			processedInInterval := currentCount - lastCount
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
			lastCount = currentCount
			lastTime = t
		}
	}
}

func (pm *ProxyManager) Report429(client429ed ctclient.Log) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for _, p := range pm.proxies {
		if p.client == client429ed {
			p.recent429sMu.Lock()
			p.recent429s = append(p.recent429s, time.Now())
			p.recent429sMu.Unlock()
			if pm.config.Verbose {
				log.Printf("ProxyManager for %s: received 429 (Too Many Requests) for proxy %s.", pm.ctlog.GetMonitoringURL(), p.address)
			}
			return
		}
	}
}

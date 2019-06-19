package main

import (
	"encoding/json"
	"github.com/prometheus/client_golang/prometheus"
	"sync"
	"time"
)

type CertificateDesc struct {
	CommonName string
	Role       string
	Expiry     time.Time
}

type MetricsCollector struct {
	certsMetric          *prometheus.Desc
	resourceErrorsMetric *prometheus.Desc
	errorsMetric         *prometheus.Desc

	role string

	resourcesUpdates chan VaultEvent
	resourceEvents   map[string]VaultEvent

	resourceErrors        chan ResourceError
	resourceErrorCounters map[ResourceError]int

	errors        chan Error
	errorCounters map[Error]int

	metricsMutex sync.RWMutex
}

type Error struct {
	err string
}

type ResourceError struct {
	resourceID string
	err        string
}

var metrics *MetricsCollector
var metricsMutex sync.Mutex

func (m MetricsCollector) init() {
	for {
		select {
		case event := <-m.resourcesUpdates:
			if event.Type == EventTypeFailure {
				continue
			}

			id := event.Resource.ID()
			m.metricsMutex.Lock()
			m.resourceEvents[id] = event
			m.metricsMutex.Unlock()
		case resourceErr := <-m.resourceErrors:
			m.metricsMutex.Lock()
			m.resourceErrorCounters[resourceErr]++
			m.metricsMutex.Unlock()
		case err := <-m.errors:
			m.metricsMutex.Lock()
			m.errorCounters[err]++
			m.metricsMutex.Unlock()
		}
	}
}

func (m *MetricsCollector) Error(err string) {
	m.errors <- Error{
		err: err,
	}
}

func (m *MetricsCollector) ResourceError(resourceID, err string) {
	m.resourceErrors <- ResourceError{
		resourceID: resourceID,
		err:        err,
	}
}

func RegisterMetricsCollector(role string, resourcesUpdates chan VaultEvent) {
	metricsMutex.Lock()
	defer metricsMutex.Unlock()

	metrics = &MetricsCollector{
		certsMetric: prometheus.NewDesc("vault_sidekick_certificate_expiry_gauge",
			"vault_sidekick_certificate_expiry_gauge",
			[]string{"common_name", "role"},
			nil,
		),
		resourceErrorsMetric: prometheus.NewDesc("vault_sidekick_resource_error_counter",
			"vault_sidekick_resource_error_counter",
			[]string{"resource", "error", "role"},
			nil,
		),
		errorsMetric: prometheus.NewDesc("vault_sidekick_error_counter",
			"vault_sidekick_error_counter",
			[]string{"error", "role"},
			nil,
		),

		role:             role,
		resourcesUpdates: resourcesUpdates,
		resourceErrors:   make(chan ResourceError, 10),
		errors:           make(chan Error, 10),

		resourceEvents:        make(map[string]VaultEvent),
		resourceErrorCounters: make(map[ResourceError]int),
		errorCounters:         make(map[Error]int),
	}

	go metrics.init()

	prometheus.MustRegister(metrics)
}

func GetMetrics() *MetricsCollector {
	metricsMutex.Lock()
	defer metricsMutex.Unlock()

	return metrics
}

func (m *MetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- m.certsMetric
	ch <- m.resourceErrorsMetric
	ch <- m.errorsMetric
}

func (m *MetricsCollector) Collect(ch chan<- prometheus.Metric) {
	m.metricsMutex.RLock()
	defer m.metricsMutex.RUnlock()

	now := time.Now()
	for resourceID, resourceEvent := range m.resourceEvents {
		certExpirationJson, ok := resourceEvent.Secret["expiration"].(json.Number)
		if !ok {
			m.Error("metrics_error")
			continue
		}

		certExpiration, err := certExpirationJson.Int64()
		if err != nil {
			m.Error("metrics_error")
			continue
		}

		expiresIn := time.Unix(certExpiration, 0).Sub(now)
		ch <- prometheus.MustNewConstMetric(m.certsMetric, prometheus.GaugeValue, expiresIn.Seconds(),
			resourceID, m.role)
	}

	for resourceErr, errCount := range m.resourceErrorCounters {
		ch <- prometheus.MustNewConstMetric(m.resourceErrorsMetric, prometheus.CounterValue, float64(errCount),
			resourceErr.resourceID, resourceErr.err, m.role)
	}

	for err, errCount := range m.errorCounters {
		ch <- prometheus.MustNewConstMetric(m.errorsMetric, prometheus.CounterValue, float64(errCount),
			err.err, m.role)
	}
}

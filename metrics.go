package main

import (
	"encoding/json"
	"github.com/prometheus/client_golang/prometheus"
	"sync"
	"time"
)

type MetricsCollector struct {
	role string

	resourceMetric       *prometheus.Desc
	resourceErrorsMetric *prometheus.Desc
	errorsMetric         *prometheus.Desc

	resourcesUpdates chan VaultEvent
	resources        map[string]VaultEvent

	resourceErrorUpdates chan ResourceError
	resourceErrors       map[ResourceError]int

	errorUpdates chan Error
	errors       map[Error]int

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
			m.resources[id] = event
			m.metricsMutex.Unlock()
		case resourceErr := <-m.resourceErrorUpdates:
			m.metricsMutex.Lock()
			m.resourceErrors[resourceErr]++
			m.metricsMutex.Unlock()
		case err := <-m.errorUpdates:
			m.metricsMutex.Lock()
			m.errors[err]++
			m.metricsMutex.Unlock()
		}
	}
}

func (m *MetricsCollector) Error(err string) {
	m.errorUpdates <- Error{
		err: err,
	}
}

func (m *MetricsCollector) ResourceError(resourceID, err string) {
	m.resourceErrorUpdates <- ResourceError{
		resourceID: resourceID,
		err:        err,
	}
}

func RegisterMetricsCollector(role string, resourcesUpdates chan VaultEvent) {
	metricsMutex.Lock()
	defer metricsMutex.Unlock()

	metrics = &MetricsCollector{
		resourceMetric: prometheus.NewDesc("vault_sidekick_certificate_expiry_gauge",
			"vault_sidekick_certificate_expiry_gauge",
			[]string{"resource_id", "role"},
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

		role: role,

		resourcesUpdates: resourcesUpdates,
		resources:        make(map[string]VaultEvent),

		resourceErrorUpdates: make(chan ResourceError, 10),
		resourceErrors:       make(map[ResourceError]int),

		errorUpdates: make(chan Error, 10),
		errors:       make(map[Error]int),
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
	ch <- m.resourceMetric
	ch <- m.resourceErrorsMetric
	ch <- m.errorsMetric
}

func (m *MetricsCollector) Collect(ch chan<- prometheus.Metric) {
	m.metricsMutex.RLock()
	defer m.metricsMutex.RUnlock()

	now := time.Now()
	for resourceID, resourceEvent := range m.resources {
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
		ch <- prometheus.MustNewConstMetric(m.resourceMetric, prometheus.GaugeValue, expiresIn.Seconds(),
			resourceID, m.role)
	}

	for resourceErr, errCount := range m.resourceErrors {
		ch <- prometheus.MustNewConstMetric(m.resourceErrorsMetric, prometheus.CounterValue, float64(errCount),
			resourceErr.resourceID, resourceErr.err, m.role)
	}

	for err, errCount := range m.errors {
		ch <- prometheus.MustNewConstMetric(m.errorsMetric, prometheus.CounterValue, float64(errCount),
			err.err, m.role)
	}
}

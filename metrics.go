package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"sync"
	"time"
)

type MetricsCollector struct {
	role string

	resourceExpiryMetric  *prometheus.Desc
	resourceTotalMetric   *prometheus.Desc
	resourceSuccessMetric *prometheus.Desc
	resourceErrorsMetric  *prometheus.Desc
	errorsMetric          *prometheus.Desc

	resourceExpiryUpdates chan ResourceExpiry
	resourceExpiry        map[string]time.Duration

	resourceTotalUpdates chan ResourceTotal
	resourceTotals       map[ResourceTotal]int

	resourceSuccessUpdates chan ResourceSuccess
	resourceSuccesses      map[ResourceSuccess]int

	resourceErrorUpdates chan ResourceError
	resourceErrors       map[ResourceError]int

	errorUpdates chan Error
	errors       map[Error]int

	metricsMutex sync.RWMutex
}

type Error struct {
	err string
}

type ResourceExpiry struct {
	resourceID string
	expiresIn time.Duration
}

type ResourceTotal struct {
	resourceID string
}

type ResourceSuccess struct {
	resourceID string
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
		case resourceExpiry := <-m.resourceExpiryUpdates:
			m.metricsMutex.Lock()
			m.resourceExpiry[resourceExpiry.resourceID] = resourceExpiry.expiresIn
			m.metricsMutex.Unlock()
		case resourceTotal := <-m.resourceTotalUpdates:
			m.metricsMutex.Lock()
			m.resourceTotals[resourceTotal]++
			m.metricsMutex.Unlock()
		case resourceSuccess := <-m.resourceSuccessUpdates:
			m.metricsMutex.Lock()
			m.resourceSuccesses[resourceSuccess]++
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

func (m *MetricsCollector) ResourceExpiry(resourceID string, expiresIn time.Duration) {
	m.resourceExpiryUpdates<- ResourceExpiry {
		resourceID: resourceID,
		expiresIn: expiresIn,
	}
}

func (m *MetricsCollector) ResourceTotal(resourceID string) {
	m.resourceTotalUpdates <- ResourceTotal{
		resourceID: resourceID,
	}
}

func (m *MetricsCollector) ResourceSuccess(resourceID string) {
	m.resourceSuccessUpdates <- ResourceSuccess{
		resourceID: resourceID,
	}
}

func (m *MetricsCollector) ResourceError(resourceID, err string) {
	m.resourceErrorUpdates <- ResourceError{
		resourceID: resourceID,
		err:        err,
	}
}

func RegisterMetricsCollector(role string) {
	metricsMutex.Lock()
	defer metricsMutex.Unlock()

	metrics = &MetricsCollector{
		resourceExpiryMetric: prometheus.NewDesc("vault_sidekick_certificate_expiry_gauge",
			"vault_sidekick_certificate_expiry_gauge",
			[]string{"resource_id", "role"},
			nil,
		),
		resourceTotalMetric: prometheus.NewDesc("vault_sidekick_resource_total_counter",
			"vault_sidekick_resource_total_counter",
			[]string{"resource", "role"},
			nil,
		),
		resourceSuccessMetric: prometheus.NewDesc("vault_sidekick_resource_success_counter",
			"vault_sidekick_resource_success_counter",
			[]string{"resource", "role"},
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

		resourceExpiryUpdates: make(chan ResourceExpiry, 10),
		resourceExpiry:        make(map[string]time.Duration),

		resourceTotalUpdates: make(chan ResourceTotal, 10),
		resourceTotals:      make(map[ResourceTotal]int),

		resourceSuccessUpdates: make(chan ResourceSuccess, 10),
		resourceSuccesses:      make(map[ResourceSuccess]int),

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
	ch <- m.resourceExpiryMetric
	ch <- m.resourceErrorsMetric
	ch <- m.errorsMetric
}

func (m *MetricsCollector) Collect(ch chan<- prometheus.Metric) {
	m.metricsMutex.RLock()
	defer m.metricsMutex.RUnlock()

	for resourceID, expiresIn := range m.resourceExpiry {
		ch <- prometheus.MustNewConstMetric(m.resourceExpiryMetric, prometheus.GaugeValue, expiresIn.Seconds(),
			resourceID, m.role)
	}

	for resourceTotal, totalCount := range m.resourceTotals{
		ch <- prometheus.MustNewConstMetric(m.resourceTotalMetric, prometheus.CounterValue, float64(totalCount),
			resourceTotal.resourceID, m.role)
	}

	for resourceSuccess, successCount := range m.resourceSuccesses {
		ch <- prometheus.MustNewConstMetric(m.resourceSuccessMetric, prometheus.CounterValue, float64(successCount),
			resourceSuccess.resourceID, m.role)
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

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

	// resourceExpiry is a map from resource ID to the latest expiry, as a duration from the current time.
	resourceExpiry        map[string]time.Duration

	// resource{Totals,Successes,Errors} tracks counts of renewals per resource ID, and whether they succeeded or failed.
	resourceTotals       map[string]int
	resourceSuccesses      map[string]int
	resourceErrors       map[string]int

	// errors Tracks counts generic, non-resource related errors, by reason.
	errors       map[string]int

	metricsMutex sync.RWMutex
}

var metrics *MetricsCollector
var metricsMutex sync.Mutex

func (m *MetricsCollector) Error(reason string) {
	m.metricsMutex.Lock()
	m.errors[reason]++
	m.metricsMutex.Unlock()
}

func (m *MetricsCollector) ResourceExpiry(resourceID string, expiresIn time.Duration) {
	m.metricsMutex.Lock()
	m.resourceExpiry[resourceID] = expiresIn
	m.metricsMutex.Unlock()
}

func (m *MetricsCollector) ResourceTotal(resourceID string) {
	m.metricsMutex.Lock()
	m.resourceTotals[resourceID]++
	m.metricsMutex.Unlock()
}

func (m *MetricsCollector) ResourceSuccess(resourceID string) {
	m.metricsMutex.Lock()
	m.resourceSuccesses[resourceID]++
	m.metricsMutex.Unlock()
}

func (m *MetricsCollector) ResourceError(resourceID string) {
	m.metricsMutex.Lock()
	m.resourceErrors[resourceID]++
	m.metricsMutex.Unlock()
}

func RegisterMetricsCollector(role string) {
	metricsMutex.Lock()
	defer metricsMutex.Unlock()

	resourceAndRoleLabels := []string{"resource_id", "role"}
	metrics = &MetricsCollector{
		resourceExpiryMetric: prometheus.NewDesc("vault_sidekick_certificate_expiry_gauge",
			"vault_sidekick_certificate_expiry_gauge",
			resourceAndRoleLabels,
			nil,
		),
		resourceTotalMetric: prometheus.NewDesc("vault_sidekick_resource_total_counter",
			"vault_sidekick_resource_total_counter",
			resourceAndRoleLabels,
			nil,
		),
		resourceSuccessMetric: prometheus.NewDesc("vault_sidekick_resource_success_counter",
			"vault_sidekick_resource_success_counter",
			resourceAndRoleLabels,
			nil,
		),
		resourceErrorsMetric: prometheus.NewDesc("vault_sidekick_resource_error_counter",
			"vault_sidekick_resource_error_counter",
			resourceAndRoleLabels,
			nil,
		),
		errorsMetric: prometheus.NewDesc("vault_sidekick_error_counter",
			"vault_sidekick_error_counter",
			[]string{"error", "role"},
			nil,
		),

		role: role,

		resourceExpiry:        make(map[string]time.Duration),

		resourceTotals:      make(map[string]int),
		resourceSuccesses:      make(map[string]int),
		resourceErrors:       make(map[string]int),

		errors:       make(map[string]int),
	}

	prometheus.MustRegister(metrics)
}

func GetMetrics() *MetricsCollector {
	metricsMutex.Lock()
	defer metricsMutex.Unlock()

	return metrics
}

func (m *MetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- m.resourceExpiryMetric
	ch <- m.resourceTotalMetric
	ch <- m.resourceSuccessMetric
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

	for resourceID, totalCount := range m.resourceTotals{
		ch <- prometheus.MustNewConstMetric(m.resourceTotalMetric, prometheus.CounterValue, float64(totalCount),
			resourceID, m.role)
	}

	for resourceID, successCount := range m.resourceSuccesses {
		ch <- prometheus.MustNewConstMetric(m.resourceSuccessMetric, prometheus.CounterValue, float64(successCount),
			resourceID, m.role)
	}

	for resourceID, errCount := range m.resourceErrors {
		ch <- prometheus.MustNewConstMetric(m.resourceErrorsMetric, prometheus.CounterValue, float64(errCount),
			resourceID, m.role)
	}

	for reason, errCount := range m.errors {
		ch <- prometheus.MustNewConstMetric(m.errorsMetric, prometheus.CounterValue, float64(errCount),
			reason, m.role)
	}
}

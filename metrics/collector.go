package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sync"
	"time"
)
type collector struct {
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

func (c *collector) ResourceExpiry(resourceID string, expiresIn time.Duration) {
	c.metricsMutex.Lock()
	c.resourceExpiry[resourceID] = expiresIn
	c.metricsMutex.Unlock()
}

func (c *collector) ResourceTotal(resourceID string) {
	c.metricsMutex.Lock()
	c.resourceTotals[resourceID]++
	c.metricsMutex.Unlock()
}

func (c *collector) ResourceSuccess(resourceID string) {
	c.metricsMutex.Lock()
	c.resourceSuccesses[resourceID]++
	c.metricsMutex.Unlock()
}

func (c *collector) ResourceError(resourceID string) {
	c.metricsMutex.Lock()
	c.resourceErrors[resourceID]++
	c.metricsMutex.Unlock()
}

func (c *collector) Error(reason string) {
	c.metricsMutex.Lock()
	c.errors[reason]++
	c.metricsMutex.Unlock()
}


func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.resourceExpiryMetric
	ch <- c.resourceTotalMetric
	ch <- c.resourceSuccessMetric
	ch <- c.resourceErrorsMetric
	ch <- c.errorsMetric
}

func (c *collector) Collect(ch chan<- prometheus.Metric) {
	c.metricsMutex.RLock()
	defer c.metricsMutex.RUnlock()

	for resourceID, expiresIn := range c.resourceExpiry {
		ch <- prometheus.MustNewConstMetric(c.resourceExpiryMetric, prometheus.GaugeValue, expiresIn.Seconds(),
			resourceID, c.role)
	}

	for resourceID, totalCount := range c.resourceTotals{
		ch <- prometheus.MustNewConstMetric(c.resourceTotalMetric, prometheus.CounterValue, float64(totalCount),
			resourceID, c.role)
	}

	for resourceID, successCount := range c.resourceSuccesses {
		ch <- prometheus.MustNewConstMetric(c.resourceSuccessMetric, prometheus.CounterValue, float64(successCount),
			resourceID, c.role)
	}

	for resourceID, errCount := range c.resourceErrors {
		ch <- prometheus.MustNewConstMetric(c.resourceErrorsMetric, prometheus.CounterValue, float64(errCount),
			resourceID, c.role)
	}

	for reason, errCount := range c.errors {
		ch <- prometheus.MustNewConstMetric(c.errorsMetric, prometheus.CounterValue, float64(errCount),
			reason, c.role)
	}
}

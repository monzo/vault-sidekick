package metrics

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type collector struct {
	resourceExpiryMetric *prometheus.Desc

	resourceTotalMetric   *prometheus.Desc
	resourceSuccessMetric *prometheus.Desc
	resourceErrorsMetric  *prometheus.Desc

	resourceProcessTotalMetric   *prometheus.Desc
	resourceProcessSuccessMetric *prometheus.Desc
	resourceProcessErrorsMetric  *prometheus.Desc

	tokenTotalMetric   *prometheus.Desc
	tokenSuccessMetric *prometheus.Desc
	tokenErrorsMetric  *prometheus.Desc

	errorsMetric *prometheus.Desc

	// resourceExpiry is a map from resource ID to the last observed expiry time of resource.
	resourceExpiry map[string]time.Time

	// resource{Totals,Successes,Errors} tracks counts of renewals per resource ID, and whether they succeeded or failed.
	resourceTotals    map[string]int64
	resourceSuccesses map[string]int64
	resourceErrors    map[string]int64

	// resourceProcess{Totals,Successes,Errors} tracks counts of resource processes (i.e. writing to disk, running exec) per resource ID, and whether they succeeded or failed.
	resourceProcessTotals    map[string]map[string]int64
	resourceProcessSuccesses map[string]map[string]int64
	resourceProcessErrors    map[string]map[string]int64

	// token{Totals,Successes,Errors} tracks counts of authentication attempts, and whether they succeeded or failed.
	tokenTotals    int64
	tokenSuccesses int64
	tokenErrors    int64

	// errors Tracks counts generic, non-resource related errors, by reason.
	errors map[string]int

	metricsMutex sync.RWMutex
}

func (c *collector) ResourceExpiry(resourceID string, expiry time.Time) {
	c.metricsMutex.Lock()
	c.resourceExpiry[resourceID] = expiry
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

func (c *collector) ResourceProcessTotal(resourceID, stage string) {
	c.metricsMutex.Lock()
	if _, ok := c.resourceProcessTotals[resourceID]; !ok {
		c.resourceProcessTotals[resourceID] = make(map[string]int64)
	}
	c.resourceProcessTotals[resourceID][stage]++
	c.metricsMutex.Unlock()
}

func (c *collector) ResourceProcessSuccess(resourceID, stage string) {
	c.metricsMutex.Lock()
	if _, ok := c.resourceProcessSuccesses[resourceID]; !ok {
		c.resourceProcessSuccesses[resourceID] = make(map[string]int64)
	}
	c.resourceProcessSuccesses[resourceID][stage]++
	c.metricsMutex.Unlock()
}

func (c *collector) ResourceProcessError(resourceID, stage string) {
	c.metricsMutex.Lock()
	if _, ok := c.resourceProcessErrors[resourceID]; !ok {
		c.resourceProcessErrors[resourceID] = make(map[string]int64)
	}
	c.resourceProcessErrors[resourceID][stage]++
	c.metricsMutex.Unlock()
}

func (c *collector) TokenTotal() {
	c.metricsMutex.Lock()
	c.tokenTotals++
	c.metricsMutex.Unlock()
}

func (c *collector) TokenSuccess() {
	c.metricsMutex.Lock()
	c.tokenSuccesses++
	c.metricsMutex.Unlock()
}

func (c *collector) TokenError() {
	c.metricsMutex.Lock()
	c.tokenErrors++
	c.metricsMutex.Unlock()
}

func (c *collector) Error(reason string) {
	c.metricsMutex.Lock()
	c.errors[reason]++
	c.metricsMutex.Unlock()
}

func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	// Expiry metric
	ch <- c.resourceExpiryMetric

	// Resource metrics
	ch <- c.resourceTotalMetric
	ch <- c.resourceSuccessMetric
	ch <- c.resourceErrorsMetric

	// Token metrics
	ch <- c.tokenTotalMetric
	ch <- c.tokenSuccessMetric
	ch <- c.tokenErrorsMetric

	// General errors metric
	ch <- c.errorsMetric
}

func (c *collector) Collect(ch chan<- prometheus.Metric) {
	c.metricsMutex.RLock()
	defer c.metricsMutex.RUnlock()

	now := time.Now()
	for resourceID, expiry := range c.resourceExpiry {
		ch <- prometheus.MustNewConstMetric(c.resourceExpiryMetric, prometheus.GaugeValue, expiry.Sub(now).Seconds(),
			resourceID)
	}

	for resourceID, totalCount := range c.resourceTotals {
		ch <- prometheus.MustNewConstMetric(c.resourceTotalMetric, prometheus.CounterValue, float64(totalCount),
			resourceID)
	}

	for resourceID, successCount := range c.resourceSuccesses {
		ch <- prometheus.MustNewConstMetric(c.resourceSuccessMetric, prometheus.CounterValue, float64(successCount),
			resourceID)
	}

	for resourceID, errCount := range c.resourceErrors {
		ch <- prometheus.MustNewConstMetric(c.resourceErrorsMetric, prometheus.CounterValue, float64(errCount),
			resourceID)
	}

	for resourceID, countsByStage := range c.resourceProcessTotals {
		for stage, count := range countsByStage {
			ch <- prometheus.MustNewConstMetric(c.resourceProcessTotalMetric, prometheus.CounterValue, float64(count),
				resourceID, stage)
		}
	}

	for resourceID, countsByStage := range c.resourceProcessSuccesses {
		for stage, count := range countsByStage {
			ch <- prometheus.MustNewConstMetric(c.resourceProcessSuccessMetric, prometheus.CounterValue, float64(count),
				resourceID, stage)
		}
	}

	for resourceID, countsByStage := range c.resourceProcessErrors {
		for stage, count := range countsByStage {
			ch <- prometheus.MustNewConstMetric(c.resourceProcessErrorsMetric, prometheus.CounterValue, float64(count),
				resourceID, stage)
		}
	}

	ch <- prometheus.MustNewConstMetric(c.tokenTotalMetric, prometheus.CounterValue, float64(c.tokenTotals))
	ch <- prometheus.MustNewConstMetric(c.tokenSuccessMetric, prometheus.CounterValue, float64(c.tokenSuccesses))
	ch <- prometheus.MustNewConstMetric(c.tokenErrorsMetric, prometheus.CounterValue, float64(c.tokenErrors))

	for reason, errCount := range c.errors {
		ch <- prometheus.MustNewConstMetric(c.errorsMetric, prometheus.CounterValue, float64(errCount),
			reason)
	}
}

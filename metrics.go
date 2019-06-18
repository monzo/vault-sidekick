package main

import (
	"encoding/json"
	"fmt"
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
	certsMetric *prometheus.Desc

	role           string
	updates        chan VaultEvent
	resourceEvents map[string]VaultEvent
	resourcesMutex sync.RWMutex
}

func (m MetricsCollector) init() {
	for {
		select {
		case event := <-m.updates:
			if event.Type == EventTypeFailure {
				continue
				// TODO: emit some nice metrics here
			}

			id := fmt.Sprintf("%v:%v", event.Resource.Resource, event.Resource.Path)
			m.resourcesMutex.Lock()
			m.resourceEvents[id] = event
			m.resourcesMutex.Unlock()
		}
	}
}

func RegisterMetricsCollector(role string, updates chan VaultEvent) {
	collector := &MetricsCollector{
		certsMetric: prometheus.NewDesc("vault_sidekick_certificate_expiry_gauge",
			"vault_sidekick_certificate_expiry_gauge",
			[]string{"common_name", "role"},
			nil,
		),
		role:           role,
		updates:        updates,
		resourceEvents: make(map[string]VaultEvent),
	}

	go collector.init()

	prometheus.MustRegister(collector)
}

func (collector *MetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- collector.certsMetric
}

func (collector *MetricsCollector) Collect(ch chan<- prometheus.Metric) {
	collector.resourcesMutex.RLock()
	defer collector.resourcesMutex.RUnlock()

	now := time.Now()
	for resourceID, resourceEvent := range collector.resourceEvents {
		certExpirationJson, ok := resourceEvent.Secret["expiration"].(json.Number)
		if !ok {
			continue
			// TODO: emit some nice metrics here
		}

		certExpiration, err := certExpirationJson.Int64()
		if err != nil {
			continue
			// TODO: emit some nice metrics here
		}

		expiresIn := time.Unix(certExpiration, 0).Sub(now)
		ch <- prometheus.MustNewConstMetric(collector.certsMetric, prometheus.GaugeValue, expiresIn.Seconds(),
			resourceID, collector.role)
	}
}

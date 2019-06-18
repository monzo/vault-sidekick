package main

import (
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"sync"
	"time"
)

type CertificateDesc struct {
	CommonName     string
	Hostname string
	Role string
	Expiry time.Time
}

type MetricsCollector struct {
	certsMetric *prometheus.Desc

	updates chan VaultEvent
	resources map[string]*VaultResource
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
			m.resources[id] = event.Resource
			m.resourcesMutex.Unlock()
		}
	}
}

func RegisterAuthMetricsCollector(updates chan VaultEvent) {
	collector := &MetricsCollector{
		certsMetric: prometheus.NewDesc("vault_sidekick_certificate_expiry_gauge",
			"vault_sidekick_certificate_expiry_gauge",
			[]string{"common_name", "hostname", "role"},
			nil,
		),
		updates:  updates,
		resources: make(map[string]*VaultResource),
	}

	go collector.init()

	prometheus.MustRegister(collector)
}

func (collector *MetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- collector.certsMetric
}

func (collector *MetricsCollector) Collect(ch chan<- prometheus.Metric) {
	now := time.Now()
	for _, cert := range collector.getCerts() {
		expiresIn := cert.Expiry.Sub(now)
		ch <- prometheus.MustNewConstMetric(collector.certsMetric, prometheus.GaugeValue, expiresIn.Seconds(),
			cert.CommonName, cert.Hostname, cert.Role)
	}
}
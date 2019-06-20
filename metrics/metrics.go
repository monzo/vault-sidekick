package metrics

import (
	"fmt"
	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
	"sync"
	"time"
)

var (
	col            *collector
	collectorMutex sync.Mutex
)

func Init(role string, metricsPort uint) {
	collectorMutex.Lock()
	defer collectorMutex.Unlock()

	resourceAndRoleLabels := []string{"resource_id", "role"}
	col = &collector{
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

	prometheus.MustRegister(col)
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		glog.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", metricsPort), nil))
	}()
}



func ResourceExpiry(resourceID string, expiresIn time.Duration) {
	col.ResourceExpiry(resourceID, expiresIn)
}

func ResourceTotal(resourceID string) {
	col.ResourceTotal(resourceID)
}

func ResourceSuccess(resourceID string) {
	col.ResourceSuccess(resourceID)
}

func ResourceError(resourceID string) {
	col.ResourceError(resourceID)
}

func Error(reason string) {
	col.Error(reason)
}

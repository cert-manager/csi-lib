/*
Copyright 2024 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package metrics

import (
	"net/http"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	// Namespace is the namespace for csi-lib metric names
	namespace = "certmanager"
	subsystem = "csi"
)

// Metrics is designed to be a shared object for updating the metrics exposed by csi-lib
type Metrics struct {
	log      logr.Logger
	registry *prometheus.Registry

	certificateRequestExpiryTimeSeconds  *prometheus.GaugeVec
	certificateRequestRenewalTimeSeconds *prometheus.GaugeVec
	certificateRequestReadyStatus        *prometheus.GaugeVec
	driverIssueCallCount                 *prometheus.CounterVec
	driverIssueErrorCount                *prometheus.CounterVec
	managedVolumeCount                   *prometheus.CounterVec
	managedCertificateCount              *prometheus.CounterVec
}

// New creates a Metrics struct and populates it with prometheus metric types.
func New(logger *logr.Logger, registry *prometheus.Registry) *Metrics {
	var (
		certificateRequestExpiryTimeSeconds = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "certificate_request_expiration_timestamp_seconds",
				Help:      "The date after which the certificate request expires. Expressed as a Unix Epoch Time.",
			},
			[]string{"name", "namespace", "issuer_name", "issuer_kind", "issuer_group"},
		)

		certificateRequestRenewalTimeSeconds = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "certificate_request_renewal_timestamp_seconds",
				Help:      "The number of seconds before expiration time the certificate request should renew.",
			},
			[]string{"name", "namespace", "issuer_name", "issuer_kind", "issuer_group"},
		)

		certificateRequestReadyStatus = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "certificate_request_ready_status",
				Help:      "The ready status of the certificate request.",
			},
			[]string{"name", "namespace", "condition", "issuer_name", "issuer_kind", "issuer_group"},
		)

		driverIssueCallCount = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "driver_issue_call_count",
				Help:      "The number of issue() calls made by the driver.",
			},
			[]string{"node", "volume"},
		)

		driverIssueErrorCount = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "driver_issue_error_count",
				Help:      "The number of errors encountered during the driver issue() calls.",
			},
			[]string{"node", "volume"},
		)

		managedVolumeCount = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "managed_volume_count",
				Help:      "The number of volume managed by the csi driver.",
			},
			[]string{"node"},
		)

		managedCertificateCount = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "managed_certificate_count",
				Help:      "The number of certificates managed by the csi driver.",
			},
			[]string{"node"},
		)
	)

	// Create server and register Prometheus metrics handler
	m := &Metrics{
		log:      logger.WithName("metrics"),
		registry: registry,

		certificateRequestExpiryTimeSeconds:  certificateRequestExpiryTimeSeconds,
		certificateRequestRenewalTimeSeconds: certificateRequestRenewalTimeSeconds,
		certificateRequestReadyStatus:        certificateRequestReadyStatus,
		driverIssueCallCount:                 driverIssueCallCount,
		driverIssueErrorCount:                driverIssueErrorCount,
		managedVolumeCount:                   managedVolumeCount,
		managedCertificateCount:              managedCertificateCount,
	}

	m.registry.MustRegister(m.certificateRequestExpiryTimeSeconds)
	m.registry.MustRegister(m.certificateRequestRenewalTimeSeconds)
	m.registry.MustRegister(m.certificateRequestReadyStatus)
	m.registry.MustRegister(m.driverIssueCallCount)
	m.registry.MustRegister(m.driverIssueErrorCount)
	m.registry.MustRegister(m.managedVolumeCount)
	m.registry.MustRegister(m.managedCertificateCount)

	return m
}

// DefaultHandler returns a default prometheus metrics HTTP handler
func (m *Metrics) DefaultHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{}))

	return mux
}

// IncrementIssueCallCount will increase the issue call counter for the driver.
func (m *Metrics) IncrementIssueCallCount(nodeNameHash, volumeID string) {
	m.driverIssueCallCount.WithLabelValues(nodeNameHash, volumeID).Inc()
}

// IncrementIssueErrorCount will increase count of errors during issue call of the driver.
func (m *Metrics) IncrementIssueErrorCount(nodeNameHash, volumeID string) {
	m.driverIssueErrorCount.WithLabelValues(nodeNameHash, volumeID).Inc()
}

// IncrementManagedVolumeCount will increase the managed volume counter for the driver.
func (m *Metrics) IncrementManagedVolumeCount(nodeNameHash string) {
	m.managedVolumeCount.WithLabelValues(nodeNameHash).Inc()
}

// IncrementManagedCertificateCount will increase the managed certificate count for the driver.
func (m *Metrics) IncrementManagedCertificateCount(nodeNameHash string) {
	m.managedCertificateCount.WithLabelValues(nodeNameHash).Inc()
}

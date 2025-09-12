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

	cmlisters "github.com/cert-manager/cert-manager/pkg/client/listers/certmanager/v1"
	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/cert-manager/csi-lib/storage"
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

	driverIssueCallCountTotal   *prometheus.CounterVec
	driverIssueErrorCountTotal  *prometheus.CounterVec
	certificateRequestCollector prometheus.Collector
}

// New creates a Metrics struct and populates it with prometheus metric types.
func New(logger *logr.Logger, registry *prometheus.Registry) *Metrics {
	var (
		// driverIssueCallCountTotal is a Prometheus counter for the number of issue() calls made by the driver.
		driverIssueCallCountTotal = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "driver_issue_call_count_total",
				Help:      "The number of issue() calls made by the driver.",
			},
			[]string{"node", "volume"},
		)

		// driverIssueErrorCountTotal is a Prometheus counter for the number of errors encountered
		// during the driver issue() calls.
		driverIssueErrorCountTotal = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "driver_issue_error_count_total",
				Help:      "The number of errors encountered during the driver issue() calls.",
			},
			[]string{"node", "volume"},
		)
	)

	registry.MustRegister(
		driverIssueCallCountTotal,
		driverIssueErrorCountTotal,
	)

	// Create server and register Prometheus metrics handler
	m := &Metrics{
		log:      logger.WithName("metrics"),
		registry: registry,

		driverIssueCallCountTotal:  driverIssueCallCountTotal,
		driverIssueErrorCountTotal: driverIssueErrorCountTotal,
	}

	return m
}

// DefaultHandler returns a default prometheus metrics HTTP handler
func (m *Metrics) DefaultHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{}))

	return mux
}

func (m *Metrics) SetupCertificateRequestCollector(nodeNameHash string, metadataReader storage.MetadataReader, certificateRequestLister cmlisters.CertificateRequestLister) {
	m.certificateRequestCollector = NewCertificateRequestCollector(nodeNameHash, metadataReader, certificateRequestLister)
	m.registry.MustRegister(m.certificateRequestCollector)
}

// IncrementIssueCallCountTotal will increase the issue call counter for the driver.
func (m *Metrics) IncrementIssueCallCountTotal(nodeNameHash, volumeID string) {
	m.driverIssueCallCountTotal.WithLabelValues(nodeNameHash, volumeID).Inc()
}

// IncrementIssueErrorCountTotal will increase count of errors during issue call of the driver.
func (m *Metrics) IncrementIssueErrorCountTotal(nodeNameHash, volumeID string) {
	m.driverIssueErrorCountTotal.WithLabelValues(nodeNameHash, volumeID).Inc()
}

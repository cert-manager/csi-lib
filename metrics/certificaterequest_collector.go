/*
Copyright 2025 The cert-manager Authors.

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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmlisters "github.com/cert-manager/cert-manager/pkg/client/listers/certmanager/v1"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"

	internalapi "github.com/cert-manager/csi-lib/internal/api"
	internalapiutil "github.com/cert-manager/csi-lib/internal/api/util"
	"github.com/cert-manager/csi-lib/storage"
)

var (
	certRequestReadyConditionStatuses     = [...]cmmeta.ConditionStatus{cmmeta.ConditionTrue, cmmeta.ConditionFalse, cmmeta.ConditionUnknown}
	certRequestReadyStatusMetric          = prometheus.NewDesc("certmanager_csi_certificate_request_ready_status", "The ready status of the certificate request.", []string{"name", "namespace", "condition", "issuer_name", "issuer_kind", "issuer_group"}, nil)
	certRequestExpirationTimestampSeconds = prometheus.NewDesc("certmanager_csi_certificate_request_expiration_timestamp_seconds", "The timestamp after which the certificate request expires, expressed in Unix Epoch Time.", []string{"name", "namespace", "issuer_name", "issuer_kind", "issuer_group"}, nil)
	certRequestRenewalTimestampSeconds    = prometheus.NewDesc("certmanager_csi_certificate_request_renewal_timestamp_seconds", "The timestamp after which the certificate request should be renewed, expressed in Unix Epoch Time.", []string{"name", "namespace", "issuer_name", "issuer_kind", "issuer_group"}, nil)
	managedVolumeCountTotal               = prometheus.NewDesc("certmanager_csi_managed_volume_count_total", "The total number of managed volumes by the csi driver.", []string{"node"}, nil)
	managedCertRequestCountTotal          = prometheus.NewDesc("certmanager_csi_managed_certificate_request_count_total", "The total number of managed certificate requests by the csi driver.", []string{"node"}, nil)
)

type CertificateRequestCollector struct {
	nodeNameHash                                 string
	metadataReader                               storage.MetadataReader
	certificateRequestLister                     cmlisters.CertificateRequestLister
	certificateRequestReadyStatusMetric          *prometheus.Desc
	certificateRequestExpirationTimestampSeconds *prometheus.Desc
	certificateRequestRenewalTimestampSeconds    *prometheus.Desc
	managedVolumeCountTotal                      *prometheus.Desc
	managedCertificateRequestCountTotal          *prometheus.Desc
}

func NewCertificateRequestCollector(nodeNameHash string, metadataReader storage.MetadataReader, certificateRequestLister cmlisters.CertificateRequestLister) prometheus.Collector {
	return &CertificateRequestCollector{
		nodeNameHash:                                 nodeNameHash,
		metadataReader:                               metadataReader,
		certificateRequestLister:                     certificateRequestLister,
		certificateRequestReadyStatusMetric:          certRequestReadyStatusMetric,
		certificateRequestExpirationTimestampSeconds: certRequestExpirationTimestampSeconds,
		certificateRequestRenewalTimestampSeconds:    certRequestRenewalTimestampSeconds,
		managedVolumeCountTotal:                      managedVolumeCountTotal,
		managedCertificateRequestCountTotal:          managedCertRequestCountTotal,
	}
}

func (cc *CertificateRequestCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- cc.certificateRequestReadyStatusMetric
	ch <- cc.certificateRequestExpirationTimestampSeconds
	ch <- cc.certificateRequestRenewalTimestampSeconds
	ch <- cc.managedVolumeCountTotal
	ch <- cc.managedCertificateRequestCountTotal
}

func (cc *CertificateRequestCollector) Collect(ch chan<- prometheus.Metric) {
	// Get the certificate requests from the lister, filtered by node selector
	nodeSelector := labels.NewSelector()
	req, err := labels.NewRequirement(internalapi.NodeIDHashLabelKey, selection.Equals, []string{cc.nodeNameHash})
	if err != nil {
		return
	}
	nodeSelector = nodeSelector.Add(*req)
	certRequestList, err := cc.certificateRequestLister.List(nodeSelector)
	if err != nil {
		return
	}
	cc.updateManagedCertificateRequestCount(len(certRequestList), ch)

	// Get the next issuance time map from the metadata reader
	nextIssuanceTimeMap, err := cc.getNextIssuanceTimeMapFromMetadata()
	if err != nil {
		return
	}
	cc.updateManagedVolumeCount(len(nextIssuanceTimeMap), ch) // each volume has one nextIssuanceTime entry

	for _, cr := range certRequestList {
		cc.updateCertificateRequestReadyStatus(cr, ch)
		cc.updateCertificateRequestExpiry(cr, ch)
		cc.updateCertificateRequestRenewalTime(cr, nextIssuanceTimeMap, ch)
	}
}

func (cc *CertificateRequestCollector) updateCertificateRequestReadyStatus(cr *cmapi.CertificateRequest, ch chan<- prometheus.Metric) {
	setMetric := func(cr *cmapi.CertificateRequest, ch chan<- prometheus.Metric, status cmmeta.ConditionStatus) {
		for _, condition := range certRequestReadyConditionStatuses {
			value := 0.0

			if status == condition {
				value = 1.0
			}

			metric := prometheus.MustNewConstMetric(
				cc.certificateRequestReadyStatusMetric, prometheus.GaugeValue,
				value,
				cr.Name,
				cr.Namespace,
				string(condition),
				cr.Spec.IssuerRef.Name,
				cr.Spec.IssuerRef.Kind,
				cr.Spec.IssuerRef.Group,
			)

			ch <- metric
		}
	}

	for _, st := range cr.Status.Conditions {
		if st.Type == cmapi.CertificateRequestConditionReady {
			setMetric(cr, ch, st.Status)
			return
		}
	}

	setMetric(cr, ch, cmmeta.ConditionUnknown)
}

func (cc *CertificateRequestCollector) updateCertificateRequestExpiry(cr *cmapi.CertificateRequest, ch chan<- prometheus.Metric) {
	expiryTime := 0.0

	if cr.Status.Certificate != nil {
		notAfter, err := getCertNotAfterTime(cr.Status.Certificate)
		if err != nil {
			return
		}
		expiryTime = float64(notAfter.Unix())
	}

	metric := prometheus.MustNewConstMetric(
		cc.certificateRequestExpirationTimestampSeconds,
		prometheus.GaugeValue,
		expiryTime,
		cr.Name,
		cr.Namespace,
		cr.Spec.IssuerRef.Name,
		cr.Spec.IssuerRef.Kind,
		cr.Spec.IssuerRef.Group,
	)

	ch <- metric
}

// updateCertificateRequestRenewalTime updates the renewal time metric for the given certificate request.
// The renewal time is the time at which the volume should be renewed.
// Note: there might be multiple certificate requests for a volume depending on the MaxRequestsPerVolume value,
// but only the latest one will be stored in the nextIssuanceTimeMap.
func (cc *CertificateRequestCollector) updateCertificateRequestRenewalTime(cr *cmapi.CertificateRequest, nextIssuanceTimeMap map[string]time.Time, ch chan<- prometheus.Metric) {
	renewalTime := 0.0

	if len(cr.Labels) != 0 {
		if nextIssuanceTime, ok := nextIssuanceTimeMap[cr.Labels[internalapi.VolumeIDHashLabelKey]]; ok {
			renewalTime = float64(nextIssuanceTime.Unix())
		}
	}

	metric := prometheus.MustNewConstMetric(
		cc.certificateRequestRenewalTimestampSeconds,
		prometheus.GaugeValue,
		renewalTime,
		cr.Name,
		cr.Namespace,
		cr.Spec.IssuerRef.Name,
		cr.Spec.IssuerRef.Kind,
		cr.Spec.IssuerRef.Group,
	)

	ch <- metric
}

// getCertNotAfterTime returns the NotAfter time of the issued certificate.
// It expects the certificate to be encoded in PEM format.
func getCertNotAfterTime(certBytes []byte) (time.Time, error) {
	block, _ := pem.Decode(certBytes)
	if block == nil {
		return time.Time{}, fmt.Errorf("invalid PEM data: could not decode certificate")
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing issued certificate: %w", err)
	}

	return crt.NotAfter, nil
}

// getNextIssuanceTimeMapFromMetadata returns a map of volume ID hashes to the next issuance time.
// The map is keyed by the volume ID hash.
// The next issuance time is the time at which the volume should be renewed.
func (cc *CertificateRequestCollector) getNextIssuanceTimeMapFromMetadata() (map[string]time.Time, error) {
	volumeIDs, err := cc.metadataReader.ListVolumes()
	if err != nil {
		return nil, fmt.Errorf("listing volumes: %w", err)
	}

	nextIssuanceTimeMap := make(map[string]time.Time, len(volumeIDs))
	for _, id := range volumeIDs {
		volumeMetadata, err := cc.metadataReader.ReadMetadata(id)
		if err != nil {
			return nil, err
		}
		if volumeMetadata.NextIssuanceTime != nil {
			nextIssuanceTimeMap[internalapiutil.HashIdentifier(id)] = *volumeMetadata.NextIssuanceTime
		}
	}
	return nextIssuanceTimeMap, nil
}

func (cc *CertificateRequestCollector) updateManagedVolumeCount(count int, ch chan<- prometheus.Metric) {
	metric := prometheus.MustNewConstMetric(
		cc.managedVolumeCountTotal,
		prometheus.CounterValue,
		float64(count),
		cc.nodeNameHash,
	)

	ch <- metric
}

func (cc *CertificateRequestCollector) updateManagedCertificateRequestCount(count int, ch chan<- prometheus.Metric) {
	metric := prometheus.MustNewConstMetric(
		cc.managedCertificateRequestCountTotal,
		prometheus.CounterValue,
		float64(count),
		cc.nodeNameHash,
	)

	ch <- metric
}

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
	"time"

	"github.com/prometheus/client_golang/prometheus"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

var readyConditionStatuses = [...]cmmeta.ConditionStatus{
	cmmeta.ConditionTrue,
	cmmeta.ConditionFalse,
	cmmeta.ConditionUnknown,
}

// UpdateCertificateRequest will update the given CertificateRequest's metrics for its expiry, renewal, and status condition.
func (m *Metrics) UpdateCertificateRequest(cr *cmapi.CertificateRequest, exp, renewal time.Time) {
	m.updateCertificateRequestExpiryAndRenewalTime(cr, exp, renewal)
	m.updateCertificateRequestStatus(cr)
}

// updateCertificateRequestExpiryAndRenewalTime updates the expiry and renewal time of a certificate request
func (m *Metrics) updateCertificateRequestExpiryAndRenewalTime(cr *cmapi.CertificateRequest, exp, renewal time.Time) {
	expiryTime := 0.0
	if !exp.IsZero() {
		expiryTime = float64(exp.Unix())
	}
	m.certificateRequestExpiryTimeSeconds.With(prometheus.Labels{
		"name":         cr.Name,
		"namespace":    cr.Namespace,
		"issuer_name":  cr.Spec.IssuerRef.Name,
		"issuer_kind":  cr.Spec.IssuerRef.Kind,
		"issuer_group": cr.Spec.IssuerRef.Group}).Set(expiryTime)

	renewalTime := 0.0
	if !renewal.IsZero() {
		renewalTime = float64(renewal.Unix())
	}
	m.certificateRequestRenewalTimeSeconds.With(prometheus.Labels{
		"name":         cr.Name,
		"namespace":    cr.Namespace,
		"issuer_name":  cr.Spec.IssuerRef.Name,
		"issuer_kind":  cr.Spec.IssuerRef.Kind,
		"issuer_group": cr.Spec.IssuerRef.Group}).Set(renewalTime)
}

// updateCertificateRequestStatus will update the metric for that Certificate Request
func (m *Metrics) updateCertificateRequestStatus(cr *cmapi.CertificateRequest) {
	for _, c := range cr.Status.Conditions {
		if c.Type == cmapi.CertificateRequestConditionReady {
			m.updateCertificateRequestReadyStatus(cr, c.Status)
			return
		}
	}

	// If no status condition set yet, set to Unknown
	m.updateCertificateRequestReadyStatus(cr, cmmeta.ConditionUnknown)
}

func (m *Metrics) updateCertificateRequestReadyStatus(cr *cmapi.CertificateRequest, current cmmeta.ConditionStatus) {
	for _, condition := range readyConditionStatuses {
		value := 0.0

		if current == condition {
			value = 1.0
		}

		m.certificateRequestReadyStatus.With(prometheus.Labels{
			"name":         cr.Name,
			"namespace":    cr.Namespace,
			"condition":    string(condition),
			"issuer_name":  cr.Spec.IssuerRef.Name,
			"issuer_kind":  cr.Spec.IssuerRef.Kind,
			"issuer_group": cr.Spec.IssuerRef.Group,
		}).Set(value)
	}
}

// RemoveCertificateRequest will delete the CertificateRequest metrics from continuing to be exposed.
func (m *Metrics) RemoveCertificateRequest(name, namespace string) {
	m.certificateRequestExpiryTimeSeconds.DeletePartialMatch(prometheus.Labels{"name": name, "namespace": namespace})
	m.certificateRequestRenewalTimeSeconds.DeletePartialMatch(prometheus.Labels{"name": name, "namespace": namespace})
	m.certificateRequestReadyStatus.DeletePartialMatch(prometheus.Labels{"name": name, "namespace": namespace})
}

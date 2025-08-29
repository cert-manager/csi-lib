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
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr/testr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	testcrypto "github.com/cert-manager/cert-manager/test/unit/crypto"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

const expiryMetadata = `
	# HELP certmanager_csi_certificate_request_expiration_timestamp_seconds The date after which the certificate request expires. Expressed as a Unix Epoch Time.
	# TYPE certmanager_csi_certificate_request_expiration_timestamp_seconds gauge
`

const renewalTimeMetadata = `
	# HELP certmanager_csi_certificate_request_renewal_timestamp_seconds The number of seconds before expiration time the certificate request should renew.
	# TYPE certmanager_csi_certificate_request_renewal_timestamp_seconds gauge
`

const readyMetadata = `
  # HELP certmanager_csi_certificate_request_ready_status The ready status of the certificate request.
  # TYPE certmanager_csi_certificate_request_ready_status gauge
`

func TestCertificateRequestMetrics(t *testing.T) {
	type testT struct {
		cr                                                 *cmapi.CertificateRequest
		notAfter, renewBefore                              time.Time
		expectedExpiry, expectedReady, expectedRenewalTime string
	}
	tests := map[string]testT{
		"certificate with expiry and ready status": {
			cr: gen.CertificateRequest("test-certificate-request",
				gen.SetCertificateRequestNamespace("test-ns"),
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name:  "test-issuer",
					Kind:  "test-issuer-kind",
					Group: "test-issuer-group",
				}),
				gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
					Type:   cmapi.CertificateRequestConditionReady,
					Status: cmmeta.ConditionTrue,
				}),
			),
			notAfter: time.Unix(2208988804, 0),

			expectedExpiry: `
	certmanager_csi_certificate_request_expiration_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate-request",namespace="test-ns"} 2.208988804e+09
`,
			expectedReady: `
        certmanager_csi_certificate_request_ready_status{condition="False",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate-request",namespace="test-ns"} 0
        certmanager_csi_certificate_request_ready_status{condition="True",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate-request",namespace="test-ns"} 1
        certmanager_csi_certificate_request_ready_status{condition="Unknown",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate-request",namespace="test-ns"} 0
`,
			expectedRenewalTime: `
		certmanager_csi_certificate_request_renewal_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate-request",namespace="test-ns"} 0
`,
		},
		"certificate with no expiry and no status should give an expiry of 0 and Unknown status": {
			cr: gen.CertificateRequest("test-certificate-request",
				gen.SetCertificateRequestNamespace("test-ns"),
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name:  "test-issuer",
					Kind:  "test-issuer-kind",
					Group: "test-issuer-group",
				}),
			),

			expectedExpiry: `
	certmanager_csi_certificate_request_expiration_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate-request",namespace="test-ns"} 0
`,
			expectedReady: `
        certmanager_csi_certificate_request_ready_status{condition="False",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate-request",namespace="test-ns"} 0
        certmanager_csi_certificate_request_ready_status{condition="True",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate-request",namespace="test-ns"} 0
        certmanager_csi_certificate_request_ready_status{condition="Unknown",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate-request",namespace="test-ns"} 1
`,
			expectedRenewalTime: `
		certmanager_csi_certificate_request_renewal_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate-request",namespace="test-ns"} 0
`,
		},
		"certificate with expiry and status False should give an expiry and False status": {
			cr: gen.CertificateRequest("test-certificate-request",
				gen.SetCertificateRequestNamespace("test-ns"),
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name:  "test-issuer",
					Kind:  "test-issuer-kind",
					Group: "test-issuer-group",
				}),
				gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
					Type:   cmapi.CertificateRequestConditionReady,
					Status: cmmeta.ConditionFalse,
				}),
			),
			notAfter: time.Unix(100, 0),

			expectedExpiry: `
	certmanager_csi_certificate_request_expiration_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate-request",namespace="test-ns"} 100
`,
			expectedReady: `
        certmanager_csi_certificate_request_ready_status{condition="False",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate-request",namespace="test-ns"} 1
        certmanager_csi_certificate_request_ready_status{condition="True",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate-request",namespace="test-ns"} 0
        certmanager_csi_certificate_request_ready_status{condition="Unknown",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate-request",namespace="test-ns"} 0
`,
			expectedRenewalTime: `
		certmanager_csi_certificate_request_renewal_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate-request",namespace="test-ns"} 0
`,
		},
		"certificate with expiry and status Unknown should give an expiry and Unknown status": {
			cr: gen.CertificateRequest("test-certificate-request",
				gen.SetCertificateRequestNamespace("test-ns"),
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name:  "test-issuer",
					Kind:  "test-issuer-kind",
					Group: "test-issuer-group",
				}),
				gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
					Type:   cmapi.CertificateRequestConditionReady,
					Status: cmmeta.ConditionUnknown,
				}),
			),
			notAfter: time.Unix(99999, 0),

			expectedExpiry: `
	certmanager_csi_certificate_request_expiration_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate-request",namespace="test-ns"} 99999
`,
			expectedReady: `
        certmanager_csi_certificate_request_ready_status{condition="False",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate-request",namespace="test-ns"} 0
        certmanager_csi_certificate_request_ready_status{condition="True",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate-request",namespace="test-ns"} 0
        certmanager_csi_certificate_request_ready_status{condition="Unknown",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate-request",namespace="test-ns"} 1
`,
			expectedRenewalTime: `
		certmanager_csi_certificate_request_renewal_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate-request",namespace="test-ns"} 0
`,
		},
		"certificate with expiry and ready status and renew before": {
			cr: gen.CertificateRequest("test-certificate-request",
				gen.SetCertificateRequestNamespace("test-ns"),
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name:  "test-issuer",
					Kind:  "test-issuer-kind",
					Group: "test-issuer-group",
				}),
				gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
					Type:   cmapi.CertificateRequestConditionReady,
					Status: cmmeta.ConditionTrue,
				}),
			),
			notAfter:    time.Unix(2208988804, 0),
			renewBefore: time.Unix(2108988804, 0),

			expectedExpiry: `
	certmanager_csi_certificate_request_expiration_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate-request",namespace="test-ns"} 2.208988804e+09
`,
			expectedReady: `
        certmanager_csi_certificate_request_ready_status{condition="False",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate-request",namespace="test-ns"} 0
        certmanager_csi_certificate_request_ready_status{condition="True",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate-request",namespace="test-ns"} 1
        certmanager_csi_certificate_request_ready_status{condition="Unknown",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate-request",namespace="test-ns"} 0
`,
			expectedRenewalTime: `
		certmanager_csi_certificate_request_renewal_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-certificate-request",namespace="test-ns"} 2.108988804e+09
`,
		},
	}
	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			testLog := testr.New(t)
			m := New(&testLog, prometheus.NewRegistry())
			m.UpdateCertificateRequest(test.cr, test.notAfter, test.renewBefore)

			if err := testutil.CollectAndCompare(m.certificateRequestExpiryTimeSeconds,
				strings.NewReader(expiryMetadata+test.expectedExpiry),
				"certmanager_csi_certificate_request_expiration_timestamp_seconds",
			); err != nil {
				t.Errorf("unexpected collecting result:\n%s", err)
			}

			if err := testutil.CollectAndCompare(m.certificateRequestRenewalTimeSeconds,
				strings.NewReader(renewalTimeMetadata+test.expectedRenewalTime),
				"certmanager_csi_certificate_request_renewal_timestamp_seconds",
			); err != nil {
				t.Errorf("unexpected collecting result:\n%s", err)
			}

			if err := testutil.CollectAndCompare(m.certificateRequestReadyStatus,
				strings.NewReader(readyMetadata+test.expectedReady),
				"certmanager_csi_certificate_request_ready_status",
			); err != nil {
				t.Errorf("unexpected collecting result:\n%s", err)
			}
		})
	}
}

func TestCertificateRequestCache(t *testing.T) {
	testLog := testr.New(t)
	m := New(&testLog, prometheus.NewRegistry())

	// private key to be used to generate X509 certificate
	privKey := testcrypto.MustCreatePEMPrivateKey(t)
	certTemplate := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test"},
		Spec: cmapi.CertificateSpec{
			CommonName: "test.example.com",
		},
	}
	notBefore := time.Unix(0, 0)
	notAfter1, notAfter2, notAfter3 :=
		time.Unix(100, 0), time.Unix(200, 0), time.Unix(300, 0)
	renew1, renew2, renew3 :=
		time.Unix(50, 0), time.Unix(150, 0), time.Unix(250, 0)

	cr1 := gen.CertificateRequest("cr1",
		gen.SetCertificateRequestNamespace("testns"),
		gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
			Name:  "test-issuer",
			Kind:  "test-issuer-kind",
			Group: "test-issuer-group",
		}),
		gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
			Type:   cmapi.CertificateRequestConditionReady,
			Status: cmmeta.ConditionUnknown,
		}),
		gen.SetCertificateRequestCertificate(
			testcrypto.MustCreateCertWithNotBeforeAfter(t, privKey, certTemplate, notBefore, notAfter1)),
	)
	cr2 := gen.CertificateRequest("cr2",
		gen.SetCertificateRequestNamespace("testns"),
		gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
			Name:  "test-issuer",
			Kind:  "test-issuer-kind",
			Group: "test-issuer-group",
		}),
		gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
			Type:   cmapi.CertificateRequestConditionReady,
			Status: cmmeta.ConditionTrue,
		}),
		gen.SetCertificateRequestCertificate(
			testcrypto.MustCreateCertWithNotBeforeAfter(t, privKey, certTemplate, notBefore, notAfter2)),
	)
	cr3 := gen.CertificateRequest("cr3",
		gen.SetCertificateRequestNamespace("testns"),
		gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
			Name:  "test-issuer",
			Kind:  "test-issuer-kind",
			Group: "test-issuer-group",
		}),
		gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
			Type:   cmapi.CertificateRequestConditionReady,
			Status: cmmeta.ConditionFalse,
		}),
		gen.SetCertificateRequestCertificate(
			testcrypto.MustCreateCertWithNotBeforeAfter(t, privKey, certTemplate, notBefore, notAfter3)),
	)

	// Observe all three Certificate metrics
	m.UpdateCertificateRequest(cr1, notAfter1, renew1)
	m.UpdateCertificateRequest(cr2, notAfter2, renew2)
	m.UpdateCertificateRequest(cr3, notAfter3, renew3)

	// Check all three metrics exist
	if err := testutil.CollectAndCompare(m.certificateRequestReadyStatus,
		strings.NewReader(readyMetadata+`
        certmanager_csi_certificate_request_ready_status{condition="False",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="cr1",namespace="testns"} 0
        certmanager_csi_certificate_request_ready_status{condition="False",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="cr2",namespace="testns"} 0
        certmanager_csi_certificate_request_ready_status{condition="False",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="cr3",namespace="testns"} 1
        certmanager_csi_certificate_request_ready_status{condition="True",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="cr1",namespace="testns"} 0
        certmanager_csi_certificate_request_ready_status{condition="True",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="cr2",namespace="testns"} 1
        certmanager_csi_certificate_request_ready_status{condition="True",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="cr3",namespace="testns"} 0
        certmanager_csi_certificate_request_ready_status{condition="Unknown",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="cr1",namespace="testns"} 1
        certmanager_csi_certificate_request_ready_status{condition="Unknown",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="cr2",namespace="testns"} 0
        certmanager_csi_certificate_request_ready_status{condition="Unknown",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="cr3",namespace="testns"} 0
`),
		"certmanager_csi_certificate_request_ready_status",
	); err != nil {
		t.Errorf("unexpected collecting result:\n%s", err)
	}
	if err := testutil.CollectAndCompare(m.certificateRequestExpiryTimeSeconds,
		strings.NewReader(expiryMetadata+`
        certmanager_csi_certificate_request_expiration_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="cr1",namespace="testns"} 100
        certmanager_csi_certificate_request_expiration_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="cr2",namespace="testns"} 200
        certmanager_csi_certificate_request_expiration_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="cr3",namespace="testns"} 300
`),
		"certmanager_csi_certificate_request_expiration_timestamp_seconds",
	); err != nil {
		t.Errorf("unexpected collecting result:\n%s", err)
	}

	if err := testutil.CollectAndCompare(m.certificateRequestRenewalTimeSeconds,
		strings.NewReader(renewalTimeMetadata+`
        certmanager_csi_certificate_request_renewal_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="cr1",namespace="testns"} 50
        certmanager_csi_certificate_request_renewal_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="cr2",namespace="testns"} 150
        certmanager_csi_certificate_request_renewal_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="cr3",namespace="testns"} 250
`),
		"certmanager_csi_certificate_request_renewal_timestamp_seconds",
	); err != nil {
		t.Errorf("unexpected collecting result:\n%s", err)
	}

	// Remove second certificate and check not exists
	m.RemoveCertificateRequest("cr2", "testns")
	if err := testutil.CollectAndCompare(m.certificateRequestReadyStatus,
		strings.NewReader(readyMetadata+`
        certmanager_csi_certificate_request_ready_status{condition="False",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="cr1",namespace="testns"} 0
        certmanager_csi_certificate_request_ready_status{condition="False",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="cr3",namespace="testns"} 1
        certmanager_csi_certificate_request_ready_status{condition="True",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="cr1",namespace="testns"} 0
        certmanager_csi_certificate_request_ready_status{condition="True",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="cr3",namespace="testns"} 0
        certmanager_csi_certificate_request_ready_status{condition="Unknown",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="cr1",namespace="testns"} 1
        certmanager_csi_certificate_request_ready_status{condition="Unknown",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="cr3",namespace="testns"} 0
`),
		"certmanager_csi_certificate_request_ready_status",
	); err != nil {
		t.Errorf("unexpected collecting result:\n%s", err)
	}
	if err := testutil.CollectAndCompare(m.certificateRequestExpiryTimeSeconds,
		strings.NewReader(expiryMetadata+`
        certmanager_csi_certificate_request_expiration_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="cr1",namespace="testns"} 100
        certmanager_csi_certificate_request_expiration_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="cr3",namespace="testns"} 300
`),
		"certmanager_csi_certificate_request_expiration_timestamp_seconds",
	); err != nil {
		t.Errorf("unexpected collecting result:\n%s", err)
	}

	// Remove all Certificates (even is already removed) and observe no Certificates
	m.RemoveCertificateRequest("cr1", "testns")
	m.RemoveCertificateRequest("cr2", "testns")
	m.RemoveCertificateRequest("cr3", "testns")
	if testutil.CollectAndCount(m.certificateRequestReadyStatus, "certmanager_csi_certificate_request_ready_status") != 0 {
		t.Errorf("unexpected collecting result")
	}
	if testutil.CollectAndCount(m.certificateRequestExpiryTimeSeconds, "certmanager_csi_certificate_request_expiration_timestamp_seconds") != 0 {
		t.Errorf("unexpected collecting result")
	}
}

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

package integration

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/fake"
	"github.com/cert-manager/cert-manager/pkg/client/informers/externalversions"
	testcrypto "github.com/cert-manager/cert-manager/test/unit/crypto"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/go-logr/logr/testr"
	"github.com/prometheus/client_golang/prometheus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	fakeclock "k8s.io/utils/clock/testing"

	"github.com/cert-manager/csi-lib/manager"
	"github.com/cert-manager/csi-lib/metadata"
	"github.com/cert-manager/csi-lib/metrics"
	"github.com/cert-manager/csi-lib/storage"
	testdriver "github.com/cert-manager/csi-lib/test/driver"
	testutil "github.com/cert-manager/csi-lib/test/util"
)

var (
	testMetrics = func(ctx context.Context, metricsEndpoint, expectedOutput string) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, metricsEndpoint, nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		output, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		trimmedOutput := strings.SplitN(string(output), "# HELP go_gc_duration_seconds", 2)[0]
		if strings.TrimSpace(trimmedOutput) != strings.TrimSpace(expectedOutput) {
			return fmt.Errorf("got unexpected metrics output\nexp:\n%s\ngot:\n%s\n",
				expectedOutput, trimmedOutput)
		}

		return nil
	}

	waitForMetrics = func(t *testing.T, ctx context.Context, metricsEndpoint, expectedOutput string) {
		var lastErr error
		err := wait.PollUntilContextCancel(ctx, time.Millisecond*100, true, func(ctx context.Context) (done bool, err error) {
			if err := testMetrics(ctx, metricsEndpoint, expectedOutput); err != nil {
				lastErr = err
				return false, nil
			}

			return true, nil
		})
		if err != nil {
			t.Fatalf("%s: failed to wait for expected metrics to be exposed: %s", err, lastErr)
		}
	}
)

func TestMetricsServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	testLog := testr.New(t)
	testNamespace := "test-ns"
	testNodeId := "test-node"

	// Build metrics handler, and start metrics server with a random available port
	store := storage.NewMemoryFS()
	fakeClient := fake.NewSimpleClientset()
	// client-go imposes a minimum resync period of 1 second, so that is the lowest we can go
	// https://github.com/kubernetes/client-go/blob/5a019202120ab4dd7dfb3788e5cb87269f343ebe/tools/cache/shared_informer.go#L575
	factory := externalversions.NewSharedInformerFactory(fakeClient, time.Second)
	certRequestInformer := factory.Certmanager().V1().CertificateRequests()
	metricsHandler := metrics.New(testNodeId, &testLog, prometheus.NewRegistry(), store, certRequestInformer.Lister())
	factory.Start(ctx.Done())
	factory.WaitForCacheSync(ctx.Done())

	// listenConfig
	listenConfig := &net.ListenConfig{}
	metricsLn, err := listenConfig.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	metricsServer := &http.Server{
		Addr:           metricsLn.Addr().String(),
		ReadTimeout:    8 * time.Second,
		WriteTimeout:   8 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MiB
		Handler:        metricsHandler.DefaultHandler(),
	}

	errCh := make(chan error)
	go func() {
		defer close(errCh)
		testLog.Info("starting metrics server", "address", metricsLn.Addr())
		if err := metricsServer.Serve(metricsLn); err != http.ErrServerClosed {
			errCh <- err
		}
	}()
	defer func() {
		// allow a timeout for graceful shutdown
		shutdownCtx, cancel := context.WithTimeout(ctx, time.Second*5)
		defer cancel()

		if err := metricsServer.Shutdown(shutdownCtx); err != nil {
			t.Fatal(err)
		}
		err := <-errCh
		if err != nil {
			t.Fatal(err)
		}
	}()

	// Build and start the driver
	clock := fakeclock.NewFakeClock(time.Now())
	opts, cl, stop := testdriver.Run(t, testdriver.Options{
		Store:   store,
		Clock:   clock,
		Metrics: metricsHandler,
		Client:  fakeClient,
		NodeID:  testNodeId,
		Log:     &testLog,
		GeneratePrivateKey: func(meta metadata.Metadata) (crypto.PrivateKey, error) {
			return nil, nil
		},
		GenerateRequest: func(meta metadata.Metadata) (*manager.CertificateRequestBundle, error) {
			return &manager.CertificateRequestBundle{
				Namespace: testNamespace,
				IssuerRef: cmmeta.ObjectReference{
					Name:  "test-issuer",
					Kind:  "test-issuer-kind",
					Group: "test-issuer-group",
				},
			}, nil
		},
		SignRequest: func(meta metadata.Metadata, key crypto.PrivateKey, request *x509.CertificateRequest) (csr []byte, err error) {
			return []byte{}, nil
		},
		WriteKeypair: func(meta metadata.Metadata, key crypto.PrivateKey, chain []byte, ca []byte) error {
			store.WriteFiles(meta, map[string][]byte{
				"ca":   ca,
				"cert": chain,
			})
			nextIssuanceTime := time.Unix(200, 0)
			meta.NextIssuanceTime = &nextIssuanceTime
			return store.WriteMetadata(meta.VolumeID, meta)
		},
	})
	defer stop()

	// Should expose no additional metrics
	metricsEndpoint := fmt.Sprintf("http://%s/metrics", metricsServer.Addr)
	waitForMetrics(t, ctx, metricsEndpoint, `# HELP certmanager_csi_managed_certificate_request_count_total The total number of managed certificate requests by the csi driver.
# TYPE certmanager_csi_managed_certificate_request_count_total counter
certmanager_csi_managed_certificate_request_count_total{node="f56fd9f8b"} 0
# HELP certmanager_csi_managed_volume_count_total The total number of managed volumes by the csi driver.
# TYPE certmanager_csi_managed_volume_count_total counter
certmanager_csi_managed_volume_count_total{node="f56fd9f8b"} 0
`)

	// Create a self-signed Certificate and wait for it to be issued
	privKey := testcrypto.MustCreatePEMPrivateKey(t)
	certTemplate := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "test"},
		Spec: cmapi.CertificateSpec{
			CommonName: "test.example.com",
		},
	}
	notBefore, notAfter := time.Unix(0, 0), time.Unix(300, 0) // renewal time will be 200
	selfSignedCertBytesWithValidity := testcrypto.MustCreateCertWithNotBeforeAfter(t, privKey, certTemplate, notBefore, notAfter)
	go testutil.IssueOneRequest(ctx, t, opts.Client, testNamespace, selfSignedCertBytesWithValidity, []byte("ca bytes"))

	// Spin up a test pod
	tmpDir, err := os.MkdirTemp("", "*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	_, err = cl.NodePublishVolume(ctx, &csi.NodePublishVolumeRequest{
		VolumeId: "test-vol",
		VolumeContext: map[string]string{
			"csi.storage.k8s.io/ephemeral":     "true",
			"csi.storage.k8s.io/pod.name":      "the-pod-name",
			"csi.storage.k8s.io/pod.namespace": testNamespace,
		},
		TargetPath: tmpDir,
		Readonly:   true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Get the CSR name
	req, err := testutil.WaitAndGetOneCertificateRequestInNamespace(ctx, opts.Client, testNamespace)
	if err != nil {
		t.Fatal(err)
	}

	// Should expose that CertificateRequest as ready with expiry and renewal time
	// node="f56fd9f8b" is the hash value of "test-node"
	expectedOutputTemplate := `# HELP certmanager_csi_certificate_request_expiration_timestamp_seconds The timestamp after which the certificate request expires, expressed in Unix Epoch Time.
# TYPE certmanager_csi_certificate_request_expiration_timestamp_seconds gauge
certmanager_csi_certificate_request_expiration_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-cr-name",namespace="test-ns"} 300
# HELP certmanager_csi_certificate_request_ready_status The ready status of the certificate request.
# TYPE certmanager_csi_certificate_request_ready_status gauge
certmanager_csi_certificate_request_ready_status{condition="False",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-cr-name",namespace="test-ns"} 0
certmanager_csi_certificate_request_ready_status{condition="True",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-cr-name",namespace="test-ns"} 1
certmanager_csi_certificate_request_ready_status{condition="Unknown",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-cr-name",namespace="test-ns"} 0
# HELP certmanager_csi_certificate_request_renewal_timestamp_seconds The timestamp after which the certificate request should be renewed, expressed in Unix Epoch Time.
# TYPE certmanager_csi_certificate_request_renewal_timestamp_seconds gauge
certmanager_csi_certificate_request_renewal_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-cr-name",namespace="test-ns"} 200
# HELP certmanager_csi_driver_issue_call_count_total The number of issue() calls made by the driver.
# TYPE certmanager_csi_driver_issue_call_count_total counter
certmanager_csi_driver_issue_call_count_total{node="f56fd9f8b",volume="test-vol"} 1
# HELP certmanager_csi_managed_certificate_request_count_total The total number of managed certificate requests by the csi driver.
# TYPE certmanager_csi_managed_certificate_request_count_total counter
certmanager_csi_managed_certificate_request_count_total{node="f56fd9f8b"} 1
# HELP certmanager_csi_managed_volume_count_total The total number of managed volumes by the csi driver.
# TYPE certmanager_csi_managed_volume_count_total counter
certmanager_csi_managed_volume_count_total{node="f56fd9f8b"} 1
`
	waitForMetrics(t, ctx, metricsEndpoint, strings.ReplaceAll(expectedOutputTemplate, "test-cr-name", req.Name))

	// Delete the test pod
	_, err = cl.NodeUnpublishVolume(ctx, &csi.NodeUnpublishVolumeRequest{
		VolumeId:   "test-vol",
		TargetPath: tmpDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = opts.Client.CertmanagerV1().CertificateRequests(testNamespace).Delete(ctx, req.Name, metav1.DeleteOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Should expose no CertificateRequest and only metrics counters
	waitForMetrics(t, ctx, metricsEndpoint, `# HELP certmanager_csi_driver_issue_call_count_total The number of issue() calls made by the driver.
# TYPE certmanager_csi_driver_issue_call_count_total counter
certmanager_csi_driver_issue_call_count_total{node="f56fd9f8b",volume="test-vol"} 1
# HELP certmanager_csi_managed_certificate_request_count_total The total number of managed certificate requests by the csi driver.
# TYPE certmanager_csi_managed_certificate_request_count_total counter
certmanager_csi_managed_certificate_request_count_total{node="f56fd9f8b"} 0
# HELP certmanager_csi_managed_volume_count_total The total number of managed volumes by the csi driver.
# TYPE certmanager_csi_managed_volume_count_total counter
certmanager_csi_managed_volume_count_total{node="f56fd9f8b"} 0
`)

}

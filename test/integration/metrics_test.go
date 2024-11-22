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

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/go-logr/logr/testr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	fakeclock "k8s.io/utils/clock/testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	testcrypto "github.com/cert-manager/cert-manager/test/unit/crypto"
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

	// Build metrics handler, and start metrics server with a random available port
	metricsHandler := metrics.New(&testLog)
	metricsLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	metricsServer := metricsHandler.NewServer(metricsLn)
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
	store := storage.NewMemoryFS()
	clock := fakeclock.NewFakeClock(time.Now())
	opts, cl, stop := testdriver.Run(t, testdriver.Options{
		Store:   store,
		Clock:   clock,
		Metrics: metricsHandler,
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
			nextIssuanceTime := clock.Now().Add(time.Hour)
			meta.NextIssuanceTime = &nextIssuanceTime
			return store.WriteMetadata(meta.VolumeID, meta)
		},
	})
	defer stop()

	// Should expose no additional metrics
	metricsEndpoint := fmt.Sprintf("http://%s/metrics", metricsServer.Addr)
	waitForMetrics(t, ctx, metricsEndpoint, "")

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
	// node="f56fd9f8b" is the hash value of "test-node" defined in driver_testing.go
	expectedOutputTemplate := `# HELP certmanager_csi_certificate_request_expiration_timestamp_seconds The date after which the certificate request expires. Expressed as a Unix Epoch Time.
# TYPE certmanager_csi_certificate_request_expiration_timestamp_seconds gauge
certmanager_csi_certificate_request_expiration_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-cr-name",namespace="test-ns"} 300
# HELP certmanager_csi_certificate_request_ready_status The ready status of the certificate request.
# TYPE certmanager_csi_certificate_request_ready_status gauge
certmanager_csi_certificate_request_ready_status{condition="False",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-cr-name",namespace="test-ns"} 0
certmanager_csi_certificate_request_ready_status{condition="True",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-cr-name",namespace="test-ns"} 1
certmanager_csi_certificate_request_ready_status{condition="Unknown",issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-cr-name",namespace="test-ns"} 0
# HELP certmanager_csi_certificate_request_renewal_timestamp_seconds The number of seconds before expiration time the certificate request should renew.
# TYPE certmanager_csi_certificate_request_renewal_timestamp_seconds gauge
certmanager_csi_certificate_request_renewal_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="test-issuer-kind",issuer_name="test-issuer",name="test-cr-name",namespace="test-ns"} 200
# HELP certmanager_csi_driver_issue_call_count The number of issue() calls made by the driver.
# TYPE certmanager_csi_driver_issue_call_count counter
certmanager_csi_driver_issue_call_count{node="f56fd9f8b",volume="test-vol"} 1
# HELP certmanager_csi_managed_certificate_count The number of certificates managed by the csi driver.
# TYPE certmanager_csi_managed_certificate_count counter
certmanager_csi_managed_certificate_count{node="f56fd9f8b"} 1
# HELP certmanager_csi_managed_volume_count The number of volume managed by the csi driver.
# TYPE certmanager_csi_managed_volume_count counter
certmanager_csi_managed_volume_count{node="f56fd9f8b"} 1
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

	// Should expose no CertificateRequest and only metrics counters
	waitForMetrics(t, ctx, metricsEndpoint, `# HELP certmanager_csi_driver_issue_call_count The number of issue() calls made by the driver.
# TYPE certmanager_csi_driver_issue_call_count counter
certmanager_csi_driver_issue_call_count{node="f56fd9f8b",volume="test-vol"} 1
# HELP certmanager_csi_managed_certificate_count The number of certificates managed by the csi driver.
# TYPE certmanager_csi_managed_certificate_count counter
certmanager_csi_managed_certificate_count{node="f56fd9f8b"} 1
# HELP certmanager_csi_managed_volume_count The number of volume managed by the csi driver.
# TYPE certmanager_csi_managed_volume_count counter
certmanager_csi_managed_volume_count{node="f56fd9f8b"} 1
`)

}

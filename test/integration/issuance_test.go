package integration

import (
	"context"
	"crypto"
	"crypto/x509"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
	fakeclock "k8s.io/utils/clock/testing"

	"github.com/cert-manager/csi-lib/manager"
	"github.com/cert-manager/csi-lib/metadata"
	"github.com/cert-manager/csi-lib/storage"
	testutil "github.com/cert-manager/csi-lib/test/util"
)

func TestIssuesCertificate(t *testing.T) {
	store := storage.NewMemoryFS()
	clock := fakeclock.NewFakeClock(time.Now())
	opts, cl, stop := testutil.RunTestDriver(t, testutil.DriverOptions{
		Store: store,
		Clock: clock,
		GeneratePrivateKey: func(meta metadata.Metadata) (crypto.PrivateKey, error) {
			return nil, nil
		},
		GenerateRequest: func(meta metadata.Metadata) (*manager.CertificateRequestBundle, error) {
			return &manager.CertificateRequestBundle{
				Namespace: "certificaterequest-namespace",
			}, nil
		},
		SignRequest: func(meta metadata.Metadata, key crypto.PrivateKey, request *x509.CertificateRequest) (csr []byte, err error) {
			return []byte{}, nil
		},
		WriteKeypair: func(meta metadata.Metadata, key crypto.PrivateKey, chain []byte, ca []byte) error {
			store.WriteFiles(meta.VolumeID, map[string][]byte{
				"ca":   ca,
				"cert": chain,
			})
			nextIssuanceTime := clock.Now().Add(time.Hour)
			meta.NextIssuanceTime = &nextIssuanceTime
			return store.WriteMetadata(meta.VolumeID, meta)
		},
	})
	defer stop()

	stopCh := make(chan struct{})
	go testutil.IssueOneRequest(t, opts.Client, "certificaterequest-namespace", stopCh, []byte("certificate bytes"), []byte("ca bytes"))
	defer close(stopCh)

	tmpDir, err := os.MkdirTemp("", "*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	_, err = cl.NodePublishVolume(context.TODO(), &csi.NodePublishVolumeRequest{
		VolumeId: "test-vol",
		VolumeContext: map[string]string{
			"csi.storage.k8s.io/ephemeral":     "true",
			"csi.storage.k8s.io/pod.name":      "the-pod-name",
			"csi.storage.k8s.io/pod.namespace": "the-pod-namespace",
		},
		TargetPath: tmpDir,
		Readonly:   true,
	})
	if err != nil {
		t.Fatal(err)
	}

	files, err := store.ReadFiles("test-vol")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(files["ca"], []byte("ca bytes")) {
		t.Errorf("unexpected CA data: %v", files["ca"])
	}
	if !reflect.DeepEqual(files["cert"], []byte("certificate bytes")) {
		t.Errorf("unexpected certificate data: %v", files["cert"])
	}
}

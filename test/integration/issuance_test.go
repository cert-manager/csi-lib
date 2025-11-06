/*
Copyright 2021 The cert-manager Authors.

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
	"crypto"
	"crypto/x509"
	"os"
	"reflect"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/container-storage-interface/spec/lib/go/csi"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakeclock "k8s.io/utils/clock/testing"

	internalapi "github.com/cert-manager/csi-lib/internal/api"
	internalapiutil "github.com/cert-manager/csi-lib/internal/api/util"
	"github.com/cert-manager/csi-lib/manager"
	"github.com/cert-manager/csi-lib/metadata"
	"github.com/cert-manager/csi-lib/storage"
	testdriver "github.com/cert-manager/csi-lib/test/driver"
	testutil "github.com/cert-manager/csi-lib/test/util"
)

// Self signed certificate valid for 'example.com' (and probably expired by the time this is read).
// This is used during test fixtures as the test driver attempts to parse the PEM certificate data,
// so we can't just use any random bytes.
var selfSignedExampleCertificate = []byte(`-----BEGIN CERTIFICATE-----
MIICxjCCAa6gAwIBAgIRAI0W8ofWt2fD+J7Cha10KwwwDQYJKoZIhvcNAQELBQAw
ADAeFw0yMjA5MTMwODI0MDBaFw0yMjEyMTIwODI0MDBaMAAwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDR2ktXXbuJPZhudwfbwiYuKjb7BfehfuRZtme4
HNvIhf0ABavuK4uRlKAKXRt1SZWMzm6P7NpTSOHjlxoBluZKFsgQbtNYYC8cBOMr
1TuU9UwAD6U4Lw+obWQppwaEYIifdSVWUqphRT2I6EJONEB9ZUr0gHMKJ2sjl163
WseSDyjPHkEM3wmpHpdDfYjNQRZ9sKB4J4/R8maW1IPpzltbryNQMfVJCYA7SjvJ
KZK5cyhabqNVeBhjBSp+UczQVrJ4ruam3i4LFUbu7DVJ/60C8knhFxGJZ5uaPbOd
eStraFOp50S3JbSpymq2m8c02ZsunUYiWCXGoh/UqrfYViVVAgMBAAGjOzA5MA4G
A1UdDwEB/wQEAwIFoDAMBgNVHRMBAf8EAjAAMBkGA1UdEQEB/wQPMA2CC2V4YW1w
bGUuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQCkAvvWIUgdpuukL8nqX3850FtHl8r9
I9oCra4Tv7fxsggFMhIbrVUjzE0NCB/kTjr5j/KFid9TFtbBo7bvYRKI1Qx12y28
CTvY1y5BqFN/lT917B+8lrWyvxsbtQ0Xhvj9JgbLhGQutR4J+ee1sKZTPqP/sSGl
PfY1JD5zWYWXWweLAR9hTp62SL6KVfsTT77jw0foehEKxfJbZY2wkdUS5GFMB8/a
KQ+2l7/qPU8XL8whXEsifoJJ+U66v3cfsH0PIhTV2JKhagljdTVf333JBD/z49qv
vnEIALrtIClFU6D/mTU5wyHhN29llwfjUgJrmYWqoWTZSiwGS6YmZpry
-----END CERTIFICATE-----`)

func TestIssuesCertificate(t *testing.T) {
	ctx := t.Context()

	store := storage.NewMemoryFS()
	clock := fakeclock.NewFakeClock(time.Now())
	opts, cl, stop := testdriver.Run(t, testdriver.Options{
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

	go testutil.IssueOneRequest(ctx, t, opts.Client, "certificaterequest-namespace", selfSignedExampleCertificate, []byte("ca bytes"))

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
	if !reflect.DeepEqual(files["cert"], selfSignedExampleCertificate) {
		t.Errorf("unexpected certificate data: %v", files["cert"])
	}
}

func TestManager_CleansUpOldRequests(t *testing.T) {
	ctx := t.Context()

	store := storage.NewMemoryFS()
	clock := fakeclock.NewFakeClock(time.Now())

	opts, cl, stop := testdriver.Run(t, testdriver.Options{
		Store:                store,
		Clock:                clock,
		MaxRequestsPerVolume: 1,
		NodeID:               "node-id",
		GenerateRequest: func(_ metadata.Metadata) (*manager.CertificateRequestBundle, error) {
			return &manager.CertificateRequestBundle{
				Namespace: "testns",
			}, nil
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

	// precreate a single certificaterequest
	crLabels := map[string]string{
		internalapi.NodeIDHashLabelKey:   internalapiutil.HashIdentifier(opts.NodeID),
		internalapi.VolumeIDHashLabelKey: internalapiutil.HashIdentifier("volume-id"),
	}
	cr := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cr",
			Namespace: "testns",
			Labels:    crLabels,
		},
		Spec:   cmapi.CertificateRequestSpec{},
		Status: cmapi.CertificateRequestStatus{},
	}
	cr, err := opts.Client.CertmanagerV1().CertificateRequests(cr.Namespace).Create(ctx, cr, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Set up a goroutine that automatically issues all CertificateRequests
	go testutil.IssueAllRequests(ctx, t, opts.Client, "testns", selfSignedExampleCertificate, []byte("ca bytes"))

	// Call NodePublishVolume
	tmpDir, err := os.MkdirTemp("", "*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	_, err = cl.NodePublishVolume(ctx, &csi.NodePublishVolumeRequest{
		VolumeId: "volume-id",
		VolumeContext: map[string]string{
			"csi.storage.k8s.io/ephemeral":     "true",
			"csi.storage.k8s.io/pod.name":      "the-pod-name",
			"csi.storage.k8s.io/pod.namespace": "testns",
		},
		TargetPath: tmpDir,
		Readonly:   true,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = opts.Client.CertmanagerV1().CertificateRequests("testns").Get(ctx, "test-cr", metav1.GetOptions{})
	if !apierrors.IsNotFound(err) {
		t.Error("Expected 'test-cr' resource to be deleted but it still exists")
	}

	all, err := opts.Client.CertmanagerV1().CertificateRequests("testns").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all.Items) != 1 {
		t.Errorf("Expected one CertificateRequest resource to still exist, but there is %d", len(all.Items))
	}
}

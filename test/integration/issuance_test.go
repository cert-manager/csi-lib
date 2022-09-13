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
	"context"
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

func TestIssuesCertificate(t *testing.T) {
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

func TestManager_CleansUpOldRequests(t *testing.T) {
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
	cr, err := opts.Client.CertmanagerV1().CertificateRequests(cr.Namespace).Create(context.TODO(), cr, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Set up a goroutine that automatically issues all CertificateRequests
	stopCh := make(chan struct{})
	go testutil.IssueAllRequests(t, opts.Client, "testns", stopCh, []byte("certificate bytes"), []byte("ca bytes"))
	defer close(stopCh)

	// Call NodePublishVolume
	tmpDir, err := os.MkdirTemp("", "*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	_, err = cl.NodePublishVolume(context.TODO(), &csi.NodePublishVolumeRequest{
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

	_, err = opts.Client.CertmanagerV1().CertificateRequests("testns").Get(context.TODO(), "test-cr", metav1.GetOptions{})
	if !apierrors.IsNotFound(err) {
		t.Error("Expected 'test-cr' resource to be deleted but it still exists")
	}

	all, err := opts.Client.CertmanagerV1().CertificateRequests("testns").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all.Items) != 1 {
		t.Errorf("Expected one CertificateRequest resource to still exist, but there is %d", len(all.Items))
	}
}

/*
Copyright 2023 The cert-manager Authors.

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
	"reflect"
	"testing"
	"time"

	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	"github.com/container-storage-interface/spec/lib/go/csi"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	fakeclock "k8s.io/utils/clock/testing"

	"github.com/cert-manager/csi-lib/manager"
	"github.com/cert-manager/csi-lib/metadata"
	"github.com/cert-manager/csi-lib/storage"
	testdriver "github.com/cert-manager/csi-lib/test/driver"
	testutil "github.com/cert-manager/csi-lib/test/util"
)

type WhenToCallIssue bool

const (
	CallIssueDuringPublish  = false
	CallIssueBetweenPublish = true
)

func testResumesExistingRequest(t *testing.T, issueBeforeCall WhenToCallIssue) {
	store := storage.NewMemoryFS()
	ns := "certificaterequest-namespace"
	clock := fakeclock.NewFakeClock(time.Now())
	opts, cl, stop := testdriver.Run(t, testdriver.Options{
		Store: store,
		Clock: clock,
		GeneratePrivateKey: func(meta metadata.Metadata) (crypto.PrivateKey, error) {
			return nil, nil
		},
		GenerateRequest: func(meta metadata.Metadata) (*manager.CertificateRequestBundle, error) {
			return &manager.CertificateRequestBundle{
				Namespace: ns,
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
	t.Cleanup(stop)

	tmpDir := t.TempDir()

	// create a root, non-expiring context
	ctx := context.Background()

	// We are going to submit this request multiple times, so lets just write it out once
	nodePublishVolumeRequest := &csi.NodePublishVolumeRequest{
		VolumeId: "test-vol",
		VolumeContext: map[string]string{
			"csi.storage.k8s.io/ephemeral":     "true",
			"csi.storage.k8s.io/pod.name":      "the-pod-name",
			"csi.storage.k8s.io/pod.namespace": ns,
		},
		TargetPath: tmpDir,
		Readonly:   true,
	}

	// create a context that expires in 2s (enough time for at least a single call of `issue`)
	twoSecondCtx, cancel := context.WithTimeout(ctx, time.Second*2)
	t.Cleanup(cancel)
	_, err := cl.NodePublishVolume(twoSecondCtx, nodePublishVolumeRequest)
	// assert that an error has been returned - we don't mind what kind of error, as due to the async nature of
	// de-registering metadata from the metadata store upon failures, there is a slim chance that a metadata read error
	// can be returned instead of a deadline exceeded error.
	if err == nil {
		t.Errorf("expected error but got nil")
	}

	// ensure a single CertificateRequest exists, and fetch its UID so we can compare it later
	existingRequestUID := ensureOneRequestExists(ctx, t, opts.Client, ns, "")

	// run NodePublishVolume once again, with a short timeout.
	// here we want to ensure that no second request is completed, and the timeout is reached again.
	// we still won't actually complete issuance here.
	twoSecondCtx, cancel = context.WithTimeout(ctx, time.Second*2)
	defer cancel()
	_, err = cl.NodePublishVolume(twoSecondCtx, nodePublishVolumeRequest)
	// assert that an error has been returned - we don't mind what kind of error, as due to the async nature of
	// de-registering metadata from the metadata store upon failures, there is a slim chance that a metadata read error
	// can be returned instead of a deadline exceeded error.
	if err == nil {
		t.Errorf("expected error but got nil")
	}
	// ensure the same certificaterequest object still exists
	ensureOneRequestExists(ctx, t, opts.Client, ns, existingRequestUID)

	stopCh := make(chan struct{})
	defer close(stopCh)
	if issueBeforeCall {
		// we don't run this in a goroutine so we can be sure the certificaterequest is completed BEFORE the issue loop is entered
		testutil.IssueOneRequest(t, opts.Client, "certificaterequest-namespace", stopCh, selfSignedExampleCertificate, []byte("ca bytes"))
	} else {
		go func() {
			// allow 500ms before actually issuing the request so we can be sure we're within the issue() function call
			// when the certificaterequest is finally completed
			time.Sleep(time.Millisecond * 500)
			testutil.IssueOneRequest(t, opts.Client, "certificaterequest-namespace", stopCh, selfSignedExampleCertificate, []byte("ca bytes"))
		}()
	}

	// call NodePublishVolume again. this time, we expect NodePublishVolume to return without an error and actually issue
	// the certificate using the existing request data.
	// We don't use an explicit timeout here to avoid any weird race conditions caused by shorter test timeouts.
	_, err = cl.NodePublishVolume(ctx, nodePublishVolumeRequest)
	if err != nil {
		t.Errorf("expected no error but got: %v", err)
	}
	// ensure the same certificaterequest object still exists
	ensureOneRequestExists(ctx, t, opts.Client, ns, existingRequestUID)

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

func TestResumesExistingRequest_IssuedBetweenPublishCalls(t *testing.T) {
	testResumesExistingRequest(t, CallIssueBetweenPublish)
}

func TestResumesExistingRequest_IssuedDuringPublishCall(t *testing.T) {
	testResumesExistingRequest(t, CallIssueDuringPublish)
}

// ensureOneRequestExists will fail the test if more than a single CertificateRequest exists.
// If permittedUID is non-empty and a request DOES exist, it will also ensure that the existing request has
// the given UID.
// It will return the UID of the existing request.
func ensureOneRequestExists(ctx context.Context, t *testing.T, client cmclient.Interface, namespace string, permittedUID types.UID) types.UID {
	// assert a single CertificateRequest object exists
	reqs, err := client.CertmanagerV1().CertificateRequests(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs.Items) != 1 {
		t.Fatalf("expected to find one existing CertificateRequest but got %d", len(reqs.Items))
	}
	req := reqs.Items[0]
	if string(permittedUID) != "" && req.UID != permittedUID {
		t.Fatalf("existing request does not have expected UID of %q - this means the request has probably been deleted and re-created", permittedUID)
	}
	return req.UID
}

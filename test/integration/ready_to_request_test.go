/*
Copyright 2022 The cert-manager Authors.

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
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/util/wait"
	fakeclock "k8s.io/utils/clock/testing"

	"github.com/cert-manager/csi-lib/manager"
	"github.com/cert-manager/csi-lib/metadata"
	"github.com/cert-manager/csi-lib/storage"
	testutil "github.com/cert-manager/csi-lib/test/util"
)

func Test_CompletesIfNotReadyToRequest_ContinueOnNotReadyEnabled(t *testing.T) {
	store := storage.NewMemoryFS()
	clock := fakeclock.NewFakeClock(time.Now())

	calls := 0
	opts, cl, stop := testutil.RunTestDriver(t, testutil.DriverOptions{
		Store:              store,
		Clock:              clock,
		ContinueOnNotReady: true,
		ReadyToRequest: func(meta metadata.Metadata) (bool, string) {
			if calls < 1 {
				calls++
				return false, "calls < 1"
			}
			// only indicate we are ready after issuance has been attempted 1 time
			return calls == 1, "calls == 1"
		},
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

	// Setup a routine to issue/sign the request IF it is created
	stopCh := make(chan struct{})
	go testutil.IssueAllRequests(t, opts.Client, "certificaterequest-namespace", stopCh, []byte("certificate bytes"), []byte("ca bytes"))
	defer close(stopCh)

	tmpDir, err := os.MkdirTemp("", "*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
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

	if err := wait.PollUntil(time.Second, func() (done bool, err error) {
		files, err := store.ReadFiles("test-vol")
		if errors.Is(err, storage.ErrNotFound) || len(files) <= 1 {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if !reflect.DeepEqual(files["ca"], []byte("ca bytes")) {
			return false, fmt.Errorf("unexpected CA data: %v", files["ca"])
		}
		if !reflect.DeepEqual(files["cert"], []byte("certificate bytes")) {
			return false, fmt.Errorf("unexpected certificate data: %v", files["cert"])
		}
		return true, nil
	}, ctx.Done()); err != nil {
		t.Error(err)
	}
}

func TestFailsIfNotReadyToRequest_ContinueOnNotReadyDisabled(t *testing.T) {
	store := storage.NewMemoryFS()
	clock := fakeclock.NewFakeClock(time.Now())

	opts, cl, stop := testutil.RunTestDriver(t, testutil.DriverOptions{
		Store:              store,
		Clock:              clock,
		ContinueOnNotReady: false,
		ReadyToRequest: func(meta metadata.Metadata) (bool, string) {
			return false, "never ready"
		},
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

	// Setup a routine to issue/sign the request IF it is created
	stopCh := make(chan struct{})
	go testutil.IssueAllRequests(t, opts.Client, "certificaterequest-namespace", stopCh, []byte("certificate bytes"), []byte("ca bytes"))
	defer close(stopCh)

	tmpDir, err := os.MkdirTemp("", "*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
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
	if status.Code(err) != codes.DeadlineExceeded {
		t.Errorf("Expected timeout to be returned from NodePublishVolume but got: %v", err)
	}

	// allow 1s for the cleanup functions in NodePublishVolume to be run
	// without this pause, the test can flake due to the storage backend not
	// being cleaned up of the persisted metadata file.
	ctx, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if wait.PollUntil(time.Millisecond*100, func() (bool, error) {
		_, err := store.ReadFiles("test-vol")
		if err != storage.ErrNotFound {
			return false, nil
		}
		return true, nil
	}, ctx.Done()); err != nil {
		t.Errorf("failed to wait for storage backend to return NotFound: %v", err)
	}
}

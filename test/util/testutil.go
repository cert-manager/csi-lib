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

package util

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/go-logr/logr"
	logrtesting "github.com/go-logr/logr/testing"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	fakeclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/fake"
	"google.golang.org/grpc"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/mount-utils"
	"k8s.io/utils/clock"

	"github.com/cert-manager/csi-lib/driver"
	"github.com/cert-manager/csi-lib/manager"
	"github.com/cert-manager/csi-lib/metadata"
	"github.com/cert-manager/csi-lib/storage"
)

type DriverOptions struct {
	Clock   clock.Clock
	Store   storage.Interface
	Log     *logr.Logger
	Client  cmclient.Interface
	Mounter mount.Interface

	NodeID               string
	MaxRequestsPerVolume int

	GeneratePrivateKey manager.GeneratePrivateKeyFunc
	GenerateRequest    manager.GenerateRequestFunc
	SignRequest        manager.SignRequestFunc
	WriteKeypair       manager.WriteKeypairFunc
}

func RunTestDriver(t *testing.T, opts DriverOptions) (DriverOptions, csi.NodeClient, func()) {
	if opts.Log == nil {
		logger := logrtesting.NewTestLogger(t)
		opts.Log = &logger
	}
	if opts.Clock == nil {
		opts.Clock = &clock.RealClock{}
	}
	if opts.Store == nil {
		opts.Store = storage.NewMemoryFS()
	}
	if opts.Client == nil {
		opts.Client = fakeclient.NewSimpleClientset()
	}
	if opts.Mounter == nil {
		opts.Mounter = mount.NewFakeMounter(nil)
	}
	if opts.NodeID == "" {
		opts.NodeID = "test-node"
	}
	if opts.GeneratePrivateKey == nil {
		opts.GeneratePrivateKey = func(_ metadata.Metadata) (crypto.PrivateKey, error) {
			return nil, nil
		}
	}
	if opts.GenerateRequest == nil {
		opts.GenerateRequest = func(_ metadata.Metadata) (*manager.CertificateRequestBundle, error) {
			return &manager.CertificateRequestBundle{}, nil
		}
	}
	if opts.SignRequest == nil {
		opts.SignRequest = func(_ metadata.Metadata, _ crypto.PrivateKey, _ *x509.CertificateRequest) ([]byte, error) {
			return []byte{}, nil
		}
	}
	if opts.WriteKeypair == nil {
		opts.WriteKeypair = func(_ metadata.Metadata, _ crypto.PrivateKey, _ []byte, _ []byte) error {
			return nil
		}
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to setup test listener: %v", err)
	}

	m := manager.NewManagerOrDie(manager.Options{
		Client:               opts.Client,
		MetadataReader:       opts.Store,
		Clock:                opts.Clock,
		Log:                  opts.Log,
		NodeID:               opts.NodeID,
		MaxRequestsPerVolume: opts.MaxRequestsPerVolume,
		GeneratePrivateKey:   opts.GeneratePrivateKey,
		GenerateRequest:      opts.GenerateRequest,
		SignRequest:          opts.SignRequest,
		WriteKeypair:         opts.WriteKeypair,
	})

	d := driver.NewWithListener(lis, *opts.Log, driver.Options{
		DriverName:    "driver-name",
		DriverVersion: "v0.0.1",
		NodeID:        opts.NodeID,
		Store:         opts.Store,
		Mounter:       opts.Mounter,
		Manager:       m,
	})

	// start the driver
	go func() {
		if err := d.Run(); err != nil {
			t.Fatalf("failed running driver: %v", err)
		}
	}()

	// create a client connection to the grpc server
	conn, err := grpc.Dial(lis.Addr().String(), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("failed to dial test server: %v", err)
	}

	return opts, csi.NewNodeClient(conn), func() {
		m.Stop()
		if err := conn.Close(); err != nil {
			t.Fatalf("error closing client connection: %v", err)
		}
		d.Stop()
		lis.Close()
	}
}

func IssueOneRequest(t *testing.T, client cmclient.Interface, namespace string, stopCh <-chan struct{}, cert, ca []byte) {
	if err := wait.PollUntil(time.Millisecond*50, func() (done bool, err error) {
		reqs, err := client.CertmanagerV1().CertificateRequests(namespace).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			return false, err
		}

		if len(reqs.Items) == 0 {
			return false, nil
		}
		if len(reqs.Items) > 1 {
			return false, fmt.Errorf("more than one CertificateRequest created")
		}

		req := reqs.Items[0]
		if len(req.Status.Certificate) != 0 {
			return false, fmt.Errorf("unexpected certificate already issued")
		}

		csr := req.DeepCopy()
		csr.Status.Conditions = append(req.Status.Conditions, cmapi.CertificateRequestCondition{
			Type:    cmapi.CertificateRequestConditionReady,
			Status:  cmmeta.ConditionTrue,
			Reason:  cmapi.CertificateRequestReasonIssued,
			Message: "Issued by test",
		})
		csr.Status.Certificate = cert
		csr.Status.CA = ca
		_, err = client.CertmanagerV1().CertificateRequests(namespace).UpdateStatus(context.TODO(), csr, metav1.UpdateOptions{})
		if err != nil {
			return false, fmt.Errorf("error updating certificaterequest status: %v", err)
		}
		return true, nil
	}, stopCh); err != nil {
		t.Errorf("error automatically issuing certificaterequest: %v", err)
	}
}

func IssueAllRequests(t *testing.T, client cmclient.Interface, namespace string, stopCh <-chan struct{}, cert, ca []byte) {
	wait.Until(func() {
		reqs, err := client.CertmanagerV1().CertificateRequests(namespace).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}

		for _, req := range reqs.Items {
			if len(req.Status.Certificate) != 0 {
				continue
			}

			csr := req.DeepCopy()
			csr.Status.Conditions = append(req.Status.Conditions, cmapi.CertificateRequestCondition{
				Type:    cmapi.CertificateRequestConditionReady,
				Status:  cmmeta.ConditionTrue,
				Reason:  cmapi.CertificateRequestReasonIssued,
				Message: "Issued by test",
			})

			csr.Status.Certificate = cert
			csr.Status.CA = ca
			_, err = client.CertmanagerV1().CertificateRequests(namespace).UpdateStatus(context.TODO(), csr, metav1.UpdateOptions{})
			if err != nil {
				t.Fatal(err)
			}
		}

	}, time.Millisecond*50, stopCh)
}

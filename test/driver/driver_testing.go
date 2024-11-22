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

package driver

import (
	"crypto"
	"crypto/x509"
	"math"
	"net"
	"testing"

	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	fakeclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/fake"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/go-logr/logr"
	"github.com/go-logr/logr/testr"
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/mount-utils"
	"k8s.io/utils/clock"

	"github.com/cert-manager/csi-lib/driver"
	"github.com/cert-manager/csi-lib/manager"
	"github.com/cert-manager/csi-lib/metadata"
	"github.com/cert-manager/csi-lib/metrics"
	"github.com/cert-manager/csi-lib/storage"
)

type Options struct {
	Clock   clock.Clock
	Store   storage.Interface
	Log     *logr.Logger
	Client  cmclient.Interface
	Mounter mount.Interface
	Metrics *metrics.Metrics

	NodeID               string
	MaxRequestsPerVolume int
	ContinueOnNotReady   bool

	GeneratePrivateKey manager.GeneratePrivateKeyFunc
	GenerateRequest    manager.GenerateRequestFunc
	SignRequest        manager.SignRequestFunc
	WriteKeypair       manager.WriteKeypairFunc
	ReadyToRequest     manager.ReadyToRequestFunc
}

func Run(t *testing.T, opts Options) (Options, csi.NodeClient, func()) {
	if opts.Log == nil {
		logger := testr.NewWithOptions(t, testr.Options{Verbosity: 999999})
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

	lc := net.ListenConfig{}
	lis, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to setup test listener: %v", err)
	}

	m := manager.NewManagerOrDie(manager.Options{
		Client:               opts.Client,
		MetadataReader:       opts.Store,
		Clock:                opts.Clock,
		Log:                  opts.Log,
		NodeID:               opts.NodeID,
		Metrics:              opts.Metrics,
		MaxRequestsPerVolume: opts.MaxRequestsPerVolume,
		GeneratePrivateKey:   opts.GeneratePrivateKey,
		GenerateRequest:      opts.GenerateRequest,
		SignRequest:          opts.SignRequest,
		WriteKeypair:         opts.WriteKeypair,
		ReadyToRequest:       opts.ReadyToRequest,
		RenewalBackoffConfig: &wait.Backoff{Steps: math.MaxInt32}, // don't actually wait (i.e. set all backoff times to 0)
	})

	d := driver.NewWithListener(lis, *opts.Log, driver.Options{
		DriverName:         "driver-name",
		DriverVersion:      "v0.0.1",
		NodeID:             opts.NodeID,
		Store:              opts.Store,
		Mounter:            opts.Mounter,
		Manager:            m,
		ContinueOnNotReady: opts.ContinueOnNotReady,
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

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
	"context"
	"net"

	"github.com/go-logr/logr"
	"k8s.io/mount-utils"

	"github.com/cert-manager/csi-lib/manager"
	"github.com/cert-manager/csi-lib/storage"
)

// A Driver is a gRPC server that implements the CSI spec.
// It can be used to build a CSI driver that generates private key data and
// automatically creates cert-manager CertificateRequests to obtain signed
// certificate data.
type Driver struct {
	server *GRPCServer
}

type Options struct {
	// DriverName should match the driver name as configured in the Kubernetes
	// CSIDriver object (e.g. 'csi.cert-manager.io')
	DriverName string
	// DriverVersion is the version of the driver to be returned during
	// IdentityServer calls
	DriverVersion string
	// NodeID is the name/ID of the node this driver is running on (typically
	// the Kubernetes node name)
	NodeID string
	// Store is a reference to a storage backend for writing files
	Store storage.Interface
	// Manager is used to fetch & renew certificate data
	Manager *manager.Manager
	// Mounter will be used to invoke operating system mount operations.
	// If not specified, the current operating system's default implementation
	// will be used (i.e. 'mount.New("")')
	Mounter mount.Interface
	// ContinueOnNotReady will cause the driver's nodeserver to continue
	// mounting the volume even if the driver is not ready to create a request yet.
	// This is useful if you need to defer requesting a certificate until after
	// initialization of the Pod (e.g. IPAM so a pod IP is allocated).
	// Enabling this option WILL cause a period of time during pod startup whereby
	// certificate data is not available in the volume whilst the process is running.
	// An `initContainer` or other special logic in the user application must be
	// added to avoid running into CrashLoopBackOff situations which can delay pod
	// start time.
	ContinueOnNotReady bool
}

func New(ctx context.Context, endpoint string, log logr.Logger, opts Options) (*Driver, error) {
	ids, cs, ns := buildServers(opts, log)
	server, err := NewGRPCServer(ctx, endpoint, log, ids, cs, ns)
	if err != nil {
		return nil, err
	}
	return &Driver{server: server}, nil
}

// NewWithListener will construct a new CSI driver using the given net.Listener.
// This is useful when more control over the listening parameters is required.
func NewWithListener(lis net.Listener, log logr.Logger, opts Options) *Driver {
	ids, cs, ns := buildServers(opts, log)
	return &Driver{server: NewGRPCServerWithListener(lis, log, ids, cs, ns)}
}

func buildServers(opts Options, log logr.Logger) (*identityServer, *controllerServer, *nodeServer) {
	if opts.Mounter == nil {
		opts.Mounter = mount.New("")
	}
	return NewIdentityServer(opts.DriverName, opts.DriverVersion), &controllerServer{}, &nodeServer{
		log:                log,
		nodeID:             opts.NodeID,
		manager:            opts.Manager,
		store:              opts.Store,
		mounter:            opts.Mounter,
		continueOnNotReady: opts.ContinueOnNotReady,
	}
}

func (d *Driver) Run() error {
	return d.server.Run()
}

func (d *Driver) Stop() {
	d.server.Stop()
}

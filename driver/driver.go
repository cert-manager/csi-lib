/*
Copyright 2021 The Jetstack cert-manager contributors.

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
	"github.com/go-logr/logr"

	"github.com/cert-manager/csi-lib/manager"
	"github.com/cert-manager/csi-lib/storage"
)

// A Driver is a gRPC server that implements the CSI spec.
// It can be used to build a CSI driver that generates private key data and
// automatically creates cert-manager CertificateRequests to obtain signed
// certificate data.
type Driver struct {
	endpoint string

	identityServer   *identityServer
	controllerServer *controllerServer
	nodeServer       *nodeServer
}

func New(driverName, driverVersion, nodeID, endpoint string, log logr.Logger, store storage.Interface, manager *manager.Manager) *Driver {
	return &Driver{
		endpoint:         endpoint,
		identityServer:   NewIdentityServer(driverName, driverVersion),
		controllerServer: &controllerServer{},
		nodeServer: &nodeServer{
			log:     log,
			nodeID:  nodeID,
			manager: manager,
			store:   store,
		},
	}
}

func (d *Driver) Run() {
	s := NewNonBlockingGRPCServer()
	s.Start(d.endpoint, d.identityServer, d.controllerServer, d.nodeServer)
	s.Wait()
}

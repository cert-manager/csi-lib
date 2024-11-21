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
	"fmt"
	"os"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/go-logr/logr"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/mount-utils"

	"github.com/cert-manager/csi-lib/manager"
	"github.com/cert-manager/csi-lib/metadata"
	"github.com/cert-manager/csi-lib/storage"
)

type nodeServer struct {
	nodeID  string
	manager *manager.Manager
	store   storage.Interface
	mounter mount.Interface

	log logr.Logger

	continueOnNotReady bool

	csi.UnimplementedNodeServer
}

var _ csi.NodeServer = &nodeServer{} // compiler checks

func (ns *nodeServer) NodePublishVolume(ctx context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
	meta := metadata.FromNodePublishVolumeRequest(req)
	log := loggerForMetadata(ns.log, meta)
	ctx, cancel := context.WithTimeout(ctx, time.Second*60)
	defer cancel()
	// clean up after ourselves if provisioning fails.
	// this is required because if publishing never succeeds, unpublish is not
	// called which leaves files around (and we may continue to renew if so).
	success := false
	defer func() {
		if !success {
			ns.manager.UnmanageVolume(req.GetVolumeId())
			_ = ns.mounter.Unmount(req.GetTargetPath())
			_ = ns.store.RemoveVolume(req.GetVolumeId())
		}
	}()

	if req.GetVolumeContext()["csi.storage.k8s.io/ephemeral"] != "true" {
		return nil, fmt.Errorf("only ephemeral volume types are supported")
	}
	if !req.GetReadonly() {
		return nil, status.Error(codes.InvalidArgument, "pod.spec.volumes[].csi.readOnly must be set to 'true'")
	}

	// If continueOnNotReady is enabled, set the NextIssuanceTime in the metadata file to epoch.
	// This allows the manager to start management for the volume again on restart if the first
	// issuance did not successfully complete.
	if meta.NextIssuanceTime == nil && ns.continueOnNotReady {
		epoch := time.Time{}
		meta.NextIssuanceTime = &epoch
	}

	if registered, err := ns.store.RegisterMetadata(meta); err != nil {
		return nil, err
	} else {
		if registered {
			log.Info("Registered new volume with storage backend")
		} else {
			log.Info("Volume already registered with storage backend")
		}
	}

	if !ns.manager.IsVolumeReady(req.GetVolumeId()) {
		// Only wait for the volume to be ready if it is in a state of 'ready to request'
		// already. This allows implementors to defer actually requesting certificates
		// until later in the pod lifecycle (e.g. after CNI has run & an IP address has been
		// allocated, if a user wants to embed pod IPs into their requests).
		isReadyToRequest, reason := ns.manager.IsVolumeReadyToRequest(req.GetVolumeId())
		if isReadyToRequest {
			log.V(4).Info("Waiting for certificate to be issued...")
			if _, err := ns.manager.ManageVolumeImmediate(ctx, req.GetVolumeId()); err != nil {
				return nil, err
			}
			log.Info("Volume registered for management")
		} else {
			if ns.continueOnNotReady {
				log.V(4).Info("Skipping waiting for certificate to be issued")
				ns.manager.ManageVolume(req.GetVolumeId())
				log.V(4).Info("Volume registered for management")
			} else {
				log.Info("Unable to request a certificate right now, will be retried", "reason", reason)
				return nil, fmt.Errorf("volume is not yet ready to be setup, will be retried: %s", reason)
			}
		}
	}

	log.Info("Ensuring data directory for volume is mounted into pod...")
	isMnt, err := ns.mounter.IsMountPoint(req.GetTargetPath())
	switch {
	case os.IsNotExist(err):
		if err := os.MkdirAll(req.GetTargetPath(), 0440); err != nil {
			return nil, err
		}
		isMnt = false
	case err != nil:
		return nil, err
	}

	if isMnt {
		// Nothing more to do if the targetPath is already a bind mount
		log.Info("Volume already mounted to pod, nothing to do")
		success = true
		return &csi.NodePublishVolumeResponse{}, nil
	}

	log.Info("Bind mounting data directory to the pod's mount namespace")
	// bind mount the targetPath to the data directory
	if err := ns.mounter.Mount(ns.store.PathForVolume(req.GetVolumeId()), req.GetTargetPath(), "", []string{"bind", "ro"}); err != nil {
		return nil, err
	}

	log.Info("Volume successfully provisioned and mounted")
	success = true

	return &csi.NodePublishVolumeResponse{}, nil
}

func loggerForMetadata(log logr.Logger, meta metadata.Metadata) logr.Logger {
	return log.WithValues("pod_name", meta.VolumeContext["csi.storage.k8s.io/pod.name"])
}

func (ns *nodeServer) NodeStageVolume(ctx context.Context, request *csi.NodeStageVolumeRequest) (*csi.NodeStageVolumeResponse, error) {
	return nil, status.Error(codes.Unimplemented, "NodeStageVolume not implemented")
}

func (ns *nodeServer) NodeUnstageVolume(ctx context.Context, request *csi.NodeUnstageVolumeRequest) (*csi.NodeUnstageVolumeResponse, error) {
	return nil, status.Error(codes.Unimplemented, "NodeUnstageVolume not implemented")
}

func (ns *nodeServer) NodeUnpublishVolume(ctx context.Context, request *csi.NodeUnpublishVolumeRequest) (*csi.NodeUnpublishVolumeResponse, error) {
	log := ns.log.WithValues("volume_id", request.VolumeId, "target_path", request.TargetPath)
	ns.manager.UnmanageVolume(request.GetVolumeId())
	log.Info("Stopped management of volume")

	isMnt, err := ns.mounter.IsMountPoint(request.GetTargetPath())
	if err != nil {
		return nil, err
	}

	if isMnt {
		if err := ns.mounter.Unmount(request.GetTargetPath()); err != nil {
			return nil, err
		}

		log.Info("Unmounted targetPath")
	}

	if err := ns.store.RemoveVolume(request.GetVolumeId()); err != nil {
		return nil, err
	}

	log.Info("Removed data directory")

	return &csi.NodeUnpublishVolumeResponse{}, nil
}

func (ns *nodeServer) NodeGetVolumeStats(ctx context.Context, request *csi.NodeGetVolumeStatsRequest) (*csi.NodeGetVolumeStatsResponse, error) {
	return nil, status.Error(codes.Unimplemented, "NodeGetVolumeStats not implemented")
}

func (ns *nodeServer) NodeExpandVolume(ctx context.Context, request *csi.NodeExpandVolumeRequest) (*csi.NodeExpandVolumeResponse, error) {
	return nil, status.Error(codes.Unimplemented, "NodeExpandVolume not implemented")
}

func (ns *nodeServer) NodeGetCapabilities(ctx context.Context, request *csi.NodeGetCapabilitiesRequest) (*csi.NodeGetCapabilitiesResponse, error) {
	return &csi.NodeGetCapabilitiesResponse{
		Capabilities: []*csi.NodeServiceCapability{
			{
				Type: &csi.NodeServiceCapability_Rpc{
					Rpc: &csi.NodeServiceCapability_RPC{
						Type: csi.NodeServiceCapability_RPC_VOLUME_MOUNT_GROUP,
					},
				},
			},
		},
	}, nil
}

func (ns *nodeServer) NodeGetInfo(ctx context.Context, request *csi.NodeGetInfoRequest) (*csi.NodeGetInfoResponse, error) {
	return &csi.NodeGetInfoResponse{
		NodeId: ns.nodeID,
	}, nil
}

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
	"k8s.io/apimachinery/pkg/util/wait"
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
}

func (ns *nodeServer) NodePublishVolume(ctx context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
	meta := metadata.FromNodePublishVolumeRequest(req)
	log := loggerForMetadata(ns.log, meta)
	ctx, _ = context.WithTimeout(ctx, time.Second*30)

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

	if registered, err := ns.store.RegisterMetadata(meta); err != nil {
		return nil, err
	} else {
		if registered {
			log.Info("Registered new volume with storage backend")
		} else {
			log.Info("Volume already registered with storage backend")
		}
	}

	if err := ns.manager.ManageVolume(req.GetVolumeId()); err != nil {
		return nil, err
	}

	log.Info("Volume registered for management")

	if err := wait.PollUntil(time.Second, func() (done bool, err error) {
		return ns.manager.IsVolumeReady(req.GetVolumeId()), nil
	}, ctx.Done()); err != nil {
		return nil, err
	}

	log.Info("Volume ready for mounting")
	notMnt, err := mount.IsNotMountPoint(ns.mounter, req.GetTargetPath())
	switch {
	case os.IsNotExist(err):
		if err := os.MkdirAll(req.GetTargetPath(), 0440); err != nil {
			return nil, err
		}
		notMnt = true
	case err != nil:
		return nil, err
	}

	if !notMnt {
		// Nothing more to do if the targetPath is already a bind mount
		success = true
		return &csi.NodePublishVolumeResponse{}, nil
	}

	log.Info("Bind mounting data directory to the targetPath")
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

	notMnt, err := mount.IsNotMountPoint(ns.mounter, request.GetTargetPath())
	if err != nil {
		return nil, err
	}
	if !notMnt {
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
						Type: csi.NodeServiceCapability_RPC_UNKNOWN,
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

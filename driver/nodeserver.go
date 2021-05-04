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
	"k8s.io/utils/mount"

	"github.com/cert-manager/csi-lib/manager"
	"github.com/cert-manager/csi-lib/metadata"
	"github.com/cert-manager/csi-lib/storage"
)

type nodeServer struct {
	nodeID  string
	manager *manager.Manager
	store   storage.Interface

	log logr.Logger
}

func (ns *nodeServer) NodePublishVolume(ctx context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
	meta := metadata.FromNodePublishVolumeRequest(req)
	log := loggerForMetadata(ns.log, meta)

	if req.GetVolumeContext()["csi.storage.k8s.io/ephemeral"] != "true" {
		return nil, fmt.Errorf("only ephemeral volume types are supported")
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

	notMnt, err := mount.IsNotMountPoint(mount.New(""), req.GetTargetPath())
	if err != nil {
		return nil, err
	}
	if !notMnt {
		// Nothing more to do if the targetPath is already a bind mount
		return &csi.NodePublishVolumeResponse{}, nil
	}

	log.Info("Bind mounting data directory to the targetPath")

	if err := os.MkdirAll(req.GetTargetPath(), 0440); err != nil {
		return nil, err
	}

	// bind mount the targetPath to the data directory
	if err := mount.New("").Mount(ns.store.PathForVolume(req.GetVolumeId()), req.GetTargetPath(), "", []string{"bind", "ro"}); err != nil {
		return nil, err
	}

	log.Info("Volume successfully provisioned and mounted")

	return &csi.NodePublishVolumeResponse{}, nil
}

func loggerForMetadata(log logr.Logger, meta metadata.Metadata) logr.Logger {
	return log.WithValues("pod_name", meta.CSIAttributes["csi.storage.k8s.io/pod.name"])
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

	notMnt, err := mount.IsNotMountPoint(mount.New(""), request.GetTargetPath())
	if err != nil {
		return nil, err
	}
	if !notMnt {
		if err := mount.New("").Unmount(request.GetTargetPath()); err != nil {
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
	return nil, status.Error(codes.Unimplemented, "")
}

func (ns *nodeServer) NodeGetInfo(ctx context.Context, request *csi.NodeGetInfoRequest) (*csi.NodeGetInfoResponse, error) {
	return &csi.NodeGetInfoResponse{
		NodeId: ns.nodeID,
	}, nil
}

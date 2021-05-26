package metadata

import (
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
)

// Metadata contains metadata about a particular CSI volume and its contents.
// It is safe to be serialised to disk for later reading (e.g. upon renewals).
type Metadata struct {
	// VolumeID as set in Node{Un,}PublishVolumeRequests.
	VolumeID string `json:"volumeID"`

	// TargetPath is the path bind mounted into the target container (e.g. in
	// Kubernetes, this is within the kubelet's 'pods' directory).
	TargetPath string `json:"targetPath"`

	// NextIssuanceTime is the time after which a re-issuance should begin.
	NextIssuanceTime *time.Time `json:"nextIssuanceTime,omitempty"`

	// System-specific attributes extracted from the NodePublishVolume request.
	// These are sourced from the VolumeContext.
	VolumeContext map[string]string `json:"volumeContext,omitempty"`
}

// FromNodePublishVolumeRequest constructs a Metadata from a NodePublishVolumeRequest.
// The NextIssuanceTime field will NOT be set.
func FromNodePublishVolumeRequest(request *csi.NodePublishVolumeRequest) Metadata {
	return Metadata{
		VolumeID:      request.GetVolumeId(),
		TargetPath:    request.GetTargetPath(),
		VolumeContext: request.GetVolumeContext(),
	}
}

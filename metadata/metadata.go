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

	// VolumeMountGroup is the filesystem group that the volume should be mounted as.
	VolumeMountGroup string `json:"volumeMountGroup,omitempty"`
}

// FromNodePublishVolumeRequest constructs a Metadata from a NodePublishVolumeRequest.
// The NextIssuanceTime field will NOT be set.
func FromNodePublishVolumeRequest(request *csi.NodePublishVolumeRequest) Metadata {
	return Metadata{
		VolumeID:         request.GetVolumeId(),
		TargetPath:       request.GetTargetPath(),
		VolumeContext:    request.GetVolumeContext(),
		VolumeMountGroup: request.GetVolumeCapability().GetMount().GetVolumeMountGroup(),
	}
}

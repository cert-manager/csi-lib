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

package storage

import (
	"encoding/json"
	"github.com/cert-manager/csi-lib/metadata"
	"sync"
)

type MemoryFS struct {
	files map[string]map[string][]byte

	lock sync.Mutex
}

var _ Interface = &MemoryFS{}

func NewMemoryFS() *MemoryFS {
	return &MemoryFS{
		files: make(map[string]map[string][]byte),
	}
}

func (m *MemoryFS) PathForVolume(volumeID string) string {
	m.lock.Lock()
	defer m.lock.Unlock()
	return volumeID
}

func (m *MemoryFS) RemoveVolume(volumeID string) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	delete(m.files, volumeID)
	return nil
}

func (m *MemoryFS) ReadMetadata(volumeID string) (metadata.Metadata, error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	volMap, ok := m.files[volumeID]
	if !ok {
		return metadata.Metadata{}, ErrNotFound
	}
	metaFile, ok := volMap["metadata.json"]
	if !ok {
		return metadata.Metadata{}, ErrNotFound
	}
	meta := &metadata.Metadata{}
	if err := json.Unmarshal(metaFile, meta); err != nil {
		return metadata.Metadata{}, ErrInvalidJSON
	}
	return *meta, nil
}

func (m *MemoryFS) ListVolumes() ([]string, error) {
	var vols []string
	for vol := range m.files {
		vols = append(vols, vol)
	}
	return vols, nil
}

func (m *MemoryFS) WriteMetadata(volumeID string, meta metadata.Metadata) error {
	vol, ok := m.files[volumeID]
	if !ok {
		return ErrNotFound
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	vol["metadata.json"] = metaJSON
	return nil
}

func (m *MemoryFS) RegisterMetadata(meta metadata.Metadata) (bool, error) {
	vol, ok := m.files[meta.VolumeID]
	if !ok {
		vol = make(map[string][]byte)
		m.files[meta.VolumeID] = vol
	}
	metaJSON, ok := vol["metadata.json"]
	if ok {
		return false, nil
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return false, err
	}
	vol["metadata.json"] = metaJSON
	return true, nil
}

func (m *MemoryFS) WriteFiles(volumeID string, files map[string][]byte) error {
	vol, ok := m.files[volumeID]
	if !ok {
		return ErrNotFound
	}
	for k, v := range files {
		vol[k] = v
	}
	return nil
}

func (m *MemoryFS) ReadFiles(volumeID string) (map[string][]byte, error) {
	vol, ok := m.files[volumeID]
	if !ok {
		return nil, ErrNotFound
	}
	return vol, nil
}

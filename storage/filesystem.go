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
	"errors"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/go-logr/logr"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/mount-utils"

	"github.com/cert-manager/csi-lib/metadata"
	"github.com/cert-manager/csi-lib/third_party/util"
)

const (
	readWriteUserFileMode        = 0600
	readOnlyUserAndGroupFileMode = 0440
)

type Filesystem struct {
	log logr.Logger

	// baseDir is the absolute path to a directory used to store all metadata
	// about mounted volumes and mount points.
	baseDir string

	// used by the 'read only' methods
	fs fs.FS
}

// Ensure the Filesystem implementation is fully featured
var _ Interface = &Filesystem{}

func NewFilesystem(log logr.Logger, baseDir string) (*Filesystem, error) {
	f := &Filesystem{
		log:     log,
		baseDir: baseDir,
		// Use the rootfs as the DirFS so that paths passed to both read &
		// write methods on this struct use a consistent root.
		fs: os.DirFS("/"),
	}

	notMnt, err := mount.IsNotMountPoint(mount.New(""), f.tempfsPath())
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		if err := os.MkdirAll(f.tempfsPath(), 0700); err != nil {
			return nil, err
		}
	}

	if notMnt {
		if err := mount.New("").Mount("tmpfs", f.tempfsPath(), "tmpfs", []string{}); err != nil {
			return nil, fmt.Errorf("mounting tmpfs: %w", err)
		}
		log.Info("Mounted new tmpfs", "path", f.tempfsPath())
	}

	return f, nil
}

func (f *Filesystem) PathForVolume(volumeID string) string {
	return f.dataPathForVolumeID(volumeID)
}

func (f *Filesystem) RemoveVolume(volumeID string) error {
	return os.RemoveAll(filepath.Join(f.tempfsPath(), volumeID))
}

func (f *Filesystem) ListVolumes() ([]string, error) {
	dirs, err := fs.ReadDir(f.fs, f.tempfsPath())
	if err != nil {
		return nil, fmt.Errorf("listing volumes: %w", err)
	}

	var vols []string
	for _, dir := range dirs {
		file, err := f.fs.Open(f.metadataPathForVolumeID(dir.Name()))
		if err != nil {
			// discovered a volume/directory that does not contain a metadata file
			// TODO: log this error to allow startup to continue
			return nil, err
		}
		// immediately close the file as we just need to verify it exists
		file.Close()
		vols = append(vols, dir.Name())
	}

	return vols, nil
}

// MetadataForVolume will return the metadata for the volume with the given ID.
// Errors wrapping ErrNotFound will be returned if metadata for the ID cannot
// be found.
func (f *Filesystem) ReadMetadata(volumeID string) (metadata.Metadata, error) {
	file, err := f.fs.Open(f.metadataPathForVolumeID(volumeID))
	if err != nil {
		// don't leak through error types from fs.Open - wrap with ErrNotFound
		// if calling Open fails, as this indicates an invalid path
		return metadata.Metadata{}, fmt.Errorf("reading metadata file: %w", ErrNotFound)
	}
	defer file.Close()

	_, err = file.Stat()
	if err == os.ErrNotExist {
		// don't leak through error types from fs.Stat - wrap with ErrNotFound
		// if calling Stat fails, as this indicates a non-existing path
		return metadata.Metadata{}, fmt.Errorf("reading metadata file: %w", ErrNotFound)
	}
	if err != nil {
		// if it's an error type we don't recognise, wrap it with %v to prevent
		// leaking through implementation details
		return metadata.Metadata{}, fmt.Errorf("reading metadata file: %v", err)
	}

	meta := metadata.Metadata{}
	if err := json.NewDecoder(file).Decode(&meta); err != nil {
		// if it's an error type we don't recognise, wrap it with %v to prevent
		// leaking through implementation details
		return metadata.Metadata{}, fmt.Errorf("reading metadata file: %w: %v", ErrInvalidJSON, err)
	}

	return meta, nil
}

func (f *Filesystem) WriteMetadata(volumeID string, meta metadata.Metadata) error {
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		// if it's an error type we don't recognise, wrap it with %v to prevent
		// leaking through implementation details
		return fmt.Errorf("%v", err)
	}

	return os.WriteFile(f.metadataPathForVolumeID(volumeID), metaBytes, readWriteUserFileMode)
}

func (f *Filesystem) RegisterMetadata(meta metadata.Metadata) (bool, error) {
	existingMeta, err := f.ReadMetadata(meta.VolumeID)
	if errors.Is(err, ErrNotFound) {
		if err := os.MkdirAll(f.volumePath(meta.VolumeID), 0644); err != nil {
			return false, err
		}

		return true, f.WriteMetadata(meta.VolumeID, meta)
	}

	if !apiequality.Semantic.DeepEqual(existingMeta.VolumeContext, meta.VolumeContext) {
		f.log.WithValues("volume_id", meta.VolumeID).Info("volume context changed, updating file system metadata")
		existingMeta.VolumeContext = meta.VolumeContext
		return true, f.WriteMetadata(existingMeta.VolumeID, existingMeta)
	}

	return false, nil
}

func (f *Filesystem) WriteFiles(volumeID string, files map[string][]byte) error {
	if err := os.MkdirAll(f.dataPathForVolumeID(volumeID), 0644); err != nil {
		return err
	}

	writer, err := util.NewAtomicWriter(f.dataPathForVolumeID(volumeID), fmt.Sprintf("volumeID %v", volumeID))
	if err != nil {
		return err
	}

	payload := makePayload(files)
	return writer.Write(payload)
}

// ReadFile reads the named file within the volume's data directory.
func (f *Filesystem) ReadFile(volumeID, name string) ([]byte, error) {
	file, err := f.fs.Open(filepath.Join(f.dataPathForVolumeID(volumeID), name))
	if err != nil {
		// don't leak through error types from fs.Open - wrap with ErrNotFound
		// if calling Open fails, as this indicates an invalid path
		return nil, ErrNotFound
	}
	defer file.Close()

	return ioutil.ReadAll(file)
}

// metadataPathForVolumeID returns the metadata.json path for the volume with
// the given ID
func (f *Filesystem) metadataPathForVolumeID(id string) string {
	return filepath.Join(f.volumePath(id), "metadata.json")
}

// dataPathForVolumeID returns the data directory for the volume with the
// given ID
func (f *Filesystem) dataPathForVolumeID(id string) string {
	return filepath.Join(f.volumePath(id), "data")
}

func (f *Filesystem) volumePath(id string) string {
	return filepath.Join(f.tempfsPath(), id)
}

func (f *Filesystem) tempfsPath() string {
	return filepath.Join(f.baseDir, "inmemfs")
}

func makePayload(in map[string][]byte) map[string]util.FileProjection {
	out := make(map[string]util.FileProjection, len(in))
	for name, data := range in {
		out[name] = util.FileProjection{
			Data: data,
			// read-only for user + group (TODO: set fsUser/fsGroup)
			Mode: readOnlyUserAndGroupFileMode,
		}
	}
	return out
}

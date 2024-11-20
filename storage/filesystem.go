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
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

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
	fs fs.StatFS

	// FixedFSGroup is an optional field which will set the gid ownership of all
	// volume's data directories to this value.
	// If this value is set, FSGroupVolumeAttributeKey has no effect.
	FixedFSGroup *int64

	// FSGroupVolumeAttributeKey is an optional well-known key in the volume
	// attributes. If this attribute is present in the context when writing
	// files, gid ownership of the volume's data directory will be changed to
	// the value. Attribute value must be a valid int64 value.
	// If FixedFSGroup is defined, this field has no effect.
	FSGroupVolumeAttributeKey string
}

// Ensure the Filesystem implementation is fully featured
var _ Interface = &Filesystem{}

func NewFilesystem(log logr.Logger, baseDir string) (*Filesystem, error) {
	f := &Filesystem{
		log:     log,
		baseDir: baseDir,
		// Use the rootfs as the DirFS so that paths passed to both read &
		// write methods on this struct use a consistent root.
		fs: os.DirFS("/").(fs.StatFS),
	}

	isMnt, err := mount.New("").IsMountPoint(f.tempfsPath())
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		if err := os.MkdirAll(f.tempfsPath(), 0700); err != nil {
			return nil, err
		}
	}

	if !isMnt {
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
		_, err := f.fs.Stat(f.metadataPathForVolumeID(dir.Name()))
		switch {
		case errors.Is(err, fs.ErrNotExist):
			f.log.Info("Directory exists but does not contain a metadata file - deleting directory and its contents", "volume_id", dir.Name())
			if err := f.RemoveVolume(dir.Name()); err != nil {
				return nil, fmt.Errorf("deleting stale volume: %v", err)
			}
			// continue to skip this loop iteration
			continue
		case err != nil:
			// discovered a volume/directory that does not contain a metadata file
			return nil, err
		}
		vols = append(vols, dir.Name())
	}

	return vols, nil
}

// ReadMetadata will return the metadata for the volume with the given ID.
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
		// Ensure directory structure for the volume exists
		if err := f.ensureVolumeDirectory(meta.VolumeID); err != nil {
			return false, err
		}

		if err := f.WriteMetadata(meta.VolumeID, meta); err != nil {
			return false, err
		}

		return true, nil
	}

	// If the volume context has changed, should write updated metadata
	if !apiequality.Semantic.DeepEqual(existingMeta.VolumeContext, meta.VolumeContext) {
		// Ensure directory structure for the volume exists - this will probably do
		// nothing, but it helps avoid any weird edge cases we could find ourselves in &
		// is an inexpensive operation.
		if err := f.ensureVolumeDirectory(meta.VolumeID); err != nil {
			return false, err
		}

		f.log.WithValues("volume_id", meta.VolumeID).Info("volume context changed, updating file system metadata")
		existingMeta.VolumeContext = meta.VolumeContext
		if err := f.WriteMetadata(existingMeta.VolumeID, existingMeta); err != nil {
			return false, err
		}

		return true, nil
	}

	return false, nil
}

// ensureVolumeDirectory ensures the directory structure for the volume exists.
// If the directories already exist, it will do nothing.
func (f *Filesystem) ensureVolumeDirectory(volumeID string) error {
	if err := os.MkdirAll(f.volumePath(volumeID), 0644); err != nil {
		return err
	}

	// Data directory should be read and execute only to the fs user and group.
	if err := os.MkdirAll(f.dataPathForVolumeID(volumeID), 0550); err != nil {
		return err
	}

	return nil
}

// WriteFiles writes the given data to filesystem files within the volume's
// data directory. Filesystem supports changing ownership of the data directory
// to a custom gid.
func (f *Filesystem) WriteFiles(meta metadata.Metadata, files map[string][]byte) error {
	// Ensure the full directory structure for the volume exists.
	// This already happens in RegisterMetadata, however, when a driver starts up and reads
	// the metadata files from the existing tmpfs to re-populate the manager, RegisterMetadata
	// is not called again (it is only invoked by driver/nodeserver.go when a pod is first processed
	// during NodePublishVolume).
	// There is a very slim chance we could end out in a weird situation where the metadata
	// file exists but the data directory does not, so re-run ensureVolumeDirectory just to be safe.
	if err := f.ensureVolumeDirectory(meta.VolumeID); err != nil {
		return err
	}

	fsGroup, err := f.fsGroupForMetadata(meta)
	if err != nil {
		return err
	}

	writer, err := util.NewAtomicWriter(f.dataPathForVolumeID(meta.VolumeID), fmt.Sprintf("volumeID %v", meta.VolumeID))
	if err != nil {
		return err
	}

	payload := makePayload(files)
	setPerms := func(tsDirName string) error {
		if fsGroup == nil {
			return nil
		}

		// Change ownership of the data directory, the timestamp directory and all files within it.
		paths := []string{
			f.dataPathForVolumeID(meta.VolumeID),
			filepath.Join(f.dataPathForVolumeID(meta.VolumeID), tsDirName),
		}
		for filename := range files {
			paths = append(paths, filepath.Join(f.dataPathForVolumeID(meta.VolumeID), tsDirName, filename))
		}

		for _, path := range paths {
			if err := os.Lchown(path, -1, int(*fsGroup)); err != nil {
				return fmt.Errorf("failed to chown data dir to gid %v: %w", *fsGroup, err)
			}
		}

		return nil
	}
	if err := writer.Write(payload, setPerms); err != nil {
		return err
	}

	return nil
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

	return io.ReadAll(file)
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
			Mode: readOnlyUserAndGroupFileMode,
		}
	}
	return out
}

// fsGroupForMetadata returns the gid that ownership of the volume data
// directory should be changed to. Returns nil if ownership should not be
// changed.
func (f *Filesystem) fsGroupForMetadata(meta metadata.Metadata) (*int64, error) {
	// FixedFSGroup takes precedence over attribute key.
	if f.FixedFSGroup != nil {
		return f.FixedFSGroup, nil
	}

	// If the FSGroupVolumeAttributeKey is not defined, no ownership can change.
	if len(f.FSGroupVolumeAttributeKey) == 0 {
		return nil, nil
	}

	fsGroupStr, ok := meta.VolumeContext[f.FSGroupVolumeAttributeKey]
	if !ok {
		// If the attribute has not been set, return no ownership change.
		return nil, nil
	}

	fsGroup, err := strconv.ParseInt(fsGroupStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %q, value must be a valid integer: %w", f.FSGroupVolumeAttributeKey, err)
	}

	// fsGroup has to be between 1 and 4294967295 inclusive. 4294967295 is the
	// largest gid number on most modern operating systems. If the actual maximum
	// is smaller on the running machine, then we will simply error later during
	// the Chown.
	if fsGroup <= 0 || fsGroup > 4294967295 {
		return nil, fmt.Errorf("%q: gid value must be greater than 0 and less than 4294967295: %d", f.FSGroupVolumeAttributeKey, fsGroup)
	}

	return &fsGroup, nil
}

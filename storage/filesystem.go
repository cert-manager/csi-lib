package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/cert-manager/csi-lib/metadata"
	"github.com/cert-manager/csi-lib/util"
)

const (
	readWriteUserFileMode        = 0600
	readOnlyUserAndGroupFileMode = 0440
)

type Filesystem struct {
	// baseDir is the absolute path to a directory used to store all metadata
	// about mounted volumes and mount points.
	baseDir string

	// used by the 'read only' methods
	fs fs.FS
}

// Ensure the Filesystem implementation is fully featured
var _ Interface = &Filesystem{}

func NewFilesystem(baseDir string) *Filesystem {
	return &Filesystem{
		baseDir: baseDir,
		// Use the rootfs as the DirFS so that paths passed to both read &
		// write methods on this struct use a consistent root.
		fs: os.DirFS("/"),
	}
}

func (f *Filesystem) PathForVolume(volumeID string) string {
	return f.dataPathForVolumeID(volumeID)
}

func (f *Filesystem) RemoveVolume(volumeID string) error {
	return os.RemoveAll(filepath.Join(f.baseDir, volumeID))
}

func (f *Filesystem) ListVolumes() ([]string, error) {
	dirs, err := fs.ReadDir(f.fs, f.baseDir)
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
	_, err := f.ReadMetadata(meta.VolumeID)
	if errors.Is(err, ErrNotFound) {
		if err := os.MkdirAll(filepath.Join(f.baseDir, meta.VolumeID), 0644); err != nil {
			return false, err
		}

		return true, f.WriteMetadata(meta.VolumeID, meta)
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
	return filepath.Join(f.baseDir, id, "metadata.json")
}

// dataPathForVolumeID returns the data directory for the volume with the
// given ID
func (f *Filesystem) dataPathForVolumeID(id string) string {
	return filepath.Join(f.baseDir, id, "data")
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

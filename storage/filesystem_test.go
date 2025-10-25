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
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cert-manager/csi-lib/metadata"
	"github.com/go-logr/logr"
)

func setupTestFolder(t *testing.T, files map[string][]byte) string {
	t.Helper()

	testDir := t.TempDir()
	for name, data := range files {
		path := filepath.Join(testDir, name)

		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatalf("failed to create directory %q: %v", filepath.Dir(path), err)
		}

		if err := os.WriteFile(path, data, 0644); err != nil {
			t.Fatalf("failed to write file %q: %v", name, err)
		}
	}

	return testDir
}

func TestFilesystem_ReadFile(t *testing.T) {
	folder := setupTestFolder(t, map[string][]byte{
		"fake-volume/data/file": []byte("hello world"),
	})

	backend, err := NewFilesystemOnDisk(logr.Discard(), folder)
	if err != nil {
		t.Fatalf("failed to create filesystem: %v", err)
	}

	d, err := backend.ReadFile("fake-volume", "file")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if string(d) != "hello world" {
		t.Errorf("expected contents 'hello world' but got: %v", string(d))
	}
}

func TestFilesystem_WriteFiles(t *testing.T) {
	parentFolderMode = 0755
	volumeFolderMode = 0755
	volumeDataFolderMode = 0755

	folder := setupTestFolder(t, map[string][]byte{})

	backend, err := NewFilesystemOnDisk(logr.Discard(), folder)
	if err != nil {
		t.Fatalf("failed to create filesystem: %v", err)
	}

	if err := backend.WriteFiles(metadata.Metadata{
		VolumeID: "fake-volume",
	}, map[string][]byte{
		"file": []byte("hello world"),
	}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	d, err := backend.ReadFile("fake-volume", "file")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if string(d) != "hello world" {
		t.Errorf("expected contents 'hello world' but got: %v", string(d))
	}
}

func TestFilesystem_ReadFile_NotFound(t *testing.T) {
	folder := setupTestFolder(t, map[string][]byte{
		"fake-volume/data/file": []byte("hello world"),
	})

	backend, err := NewFilesystemOnDisk(logr.Discard(), folder)
	if err != nil {
		t.Fatalf("failed to create filesystem: %v", err)
	}

	_, err = backend.ReadFile("fake-volume", "file2")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected %v but got: %v", ErrNotFound, err)
	}
}

func TestFilesystem_MetadataForVolume_NotFound(t *testing.T) {
	folder := setupTestFolder(t, map[string][]byte{})

	backend, err := NewFilesystemOnDisk(logr.Discard(), folder)
	if err != nil {
		t.Fatalf("failed to create filesystem: %v", err)
	}

	_, err = backend.ReadMetadata("fake-volume")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected %v but got: %v", ErrNotFound, err)
	}
}

func TestFilesystem_MetadataForVolume_InvalidJSON(t *testing.T) {
	folder := setupTestFolder(t, map[string][]byte{
		"fake-volume/metadata.json": []byte("{"),
	})

	backend, err := NewFilesystemOnDisk(logr.Discard(), folder)
	if err != nil {
		t.Fatalf("failed to create filesystem: %v", err)
	}

	_, err = backend.ReadMetadata("fake-volume")
	if !errors.Is(err, ErrInvalidJSON) {
		t.Errorf("expected %v but got: %v", ErrInvalidJSON, err)
	}
}

func TestFilesystem_MetadataForVolume(t *testing.T) {
	folder := setupTestFolder(t, map[string][]byte{
		"fake-volume/metadata.json": []byte(`{"volumeID": "fake-volume", "targetPath": "/fake-volume", "volumeContext": {"a": "b"}}`),
	})

	backend, err := NewFilesystemOnDisk(logr.Discard(), folder)
	if err != nil {
		t.Fatalf("failed to create filesystem: %v", err)
	}

	meta, err := backend.ReadMetadata("fake-volume")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !reflect.DeepEqual(meta, metadata.Metadata{
		VolumeID:      "fake-volume",
		TargetPath:    "/fake-volume",
		VolumeContext: map[string]string{"a": "b"},
	}) {
		t.Errorf("unexpected metadata: %#v", meta)
	}
}

func TestFilesystem_ListVolumes(t *testing.T) {
	folder := setupTestFolder(t, map[string][]byte{
		"fake-volume/metadata.json": {},
	})

	backend, err := NewFilesystemOnDisk(logr.Discard(), folder)
	if err != nil {
		t.Fatalf("failed to create filesystem: %v", err)
	}

	vols, err := backend.ListVolumes()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(vols) != 1 {
		t.Errorf("expected 1 volume to be returned but got: %+v", vols)
	}
	if vols[0] != "fake-volume" {
		t.Errorf("expected only entry to be 'fake-volume' but got: %s", vols[0])
	}
}

func TestFilesystem_ListVolumes_CleansUpCorruptVolumes(t *testing.T) {
	folder := setupTestFolder(t, map[string][]byte{
		"fake-volume/metadata.json": {},
		"fake-emptyvolume/nothing":  {},
	})

	backend, err := NewFilesystemOnDisk(logr.Discard(), folder)
	if err != nil {
		t.Fatalf("failed to create filesystem: %v", err)
	}

	vols, err := backend.ListVolumes()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(vols) != 1 {
		t.Errorf("expected 1 volume to be returned but got: %+v", vols)
	}
	if vols[0] != "fake-volume" {
		t.Errorf("expected only entry to be 'fake-volume' but got: %s", vols[0])
	}
}
func Test_fsGroupForMetadata(t *testing.T) {
	intPtr := func(i int64) *int64 {
		return &i
	}

	tests := map[string]struct {
		metaVolumeMountGroup      string
		fsGroupVolumeAttributeKey string
		volumeContext             map[string]string

		expGID *int64
		expErr bool
	}{
		"meta.VolumeMountGroup='' FSGroupVolumeAttributeKey='', should return nil gid": {
			metaVolumeMountGroup:      "",
			fsGroupVolumeAttributeKey: "",
			volumeContext:             map[string]string{},
			expGID:                    nil,
			expErr:                    false,
		},
		"meta.VolumeMountGroup='70' FSGroupVolumeAttributeKey='', should return 70": {
			metaVolumeMountGroup:      "70",
			fsGroupVolumeAttributeKey: "",
			volumeContext:             map[string]string{},
			expGID:                    intPtr(70),
			expErr:                    false,
		},
		"meta.VolumeMountGroup='' FSGroupVolumeAttributeKey=defined but not present in context, should return nil": {
			metaVolumeMountGroup:      "",
			fsGroupVolumeAttributeKey: "fs-gid",
			volumeContext:             map[string]string{},
			expGID:                    nil,
			expErr:                    false,
		},
		"meta.VolumeMountGroup='70' FSGroupVolumeAttributeKey=defined but not present in context, should return 70": {
			metaVolumeMountGroup:      "70",
			fsGroupVolumeAttributeKey: "fs-gid",
			volumeContext:             map[string]string{},
			expGID:                    intPtr(70),
			expErr:                    false,
		},
		"meta.VolumeMountGroup='' FSGroupVolumeAttributeKey=defined and present in context, should return 20": {
			metaVolumeMountGroup:      "",
			fsGroupVolumeAttributeKey: "fs-gid",
			volumeContext: map[string]string{
				"fs-gid": "20",
			},
			expGID: intPtr(20),
			expErr: false,
		},
		"meta.VolumeMountGroup='10' FSGroupVolumeAttributeKey=defined and present in context, should return 20": {
			metaVolumeMountGroup:      "10",
			fsGroupVolumeAttributeKey: "fs-gid",
			volumeContext: map[string]string{
				"fs-gid": "20",
			},
			expGID: intPtr(20),
			expErr: false,
		},
		"meta.VolumeMountGroup='' FSGroupVolumeAttributeKey=defined and present in context but value of 0, should error": {
			metaVolumeMountGroup:      "",
			fsGroupVolumeAttributeKey: "fs-gid",
			volumeContext: map[string]string{
				"fs-gid": "0",
			},
			expGID: nil,
			expErr: true,
		},
		"meta.VolumeMountGroup='' FSGroupVolumeAttributeKey=defined and present in context but value of -1, should error": {
			metaVolumeMountGroup:      "",
			fsGroupVolumeAttributeKey: "fs-gid",
			volumeContext: map[string]string{
				"fs-gid": "-1",
			},
			expGID: nil,
			expErr: true,
		},
		"meta.VolumeMountGroup='' FSGroupVolumeAttributeKey=defined and present in context but value greater than the max gid, should error": {
			metaVolumeMountGroup:      "",
			fsGroupVolumeAttributeKey: "fs-gid",
			volumeContext: map[string]string{
				"fs-gid": "4294967296",
			},
			expGID: nil,
			expErr: true,
		},
		"meta.VolumeMountGroup='' FSGroupVolumeAttributeKey=defined and present in context but with bad value, should return error": {
			metaVolumeMountGroup:      "",
			fsGroupVolumeAttributeKey: "fs-gid",
			volumeContext: map[string]string{
				"fs-gid": "bad-value",
			},
			expGID: nil,
			expErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			f := Filesystem{
				FSGroupVolumeAttributeKey: test.fsGroupVolumeAttributeKey,
			}

			gid, err := f.fsGroupForMetadata(metadata.Metadata{
				VolumeContext:    test.volumeContext,
				VolumeMountGroup: test.metaVolumeMountGroup,
			})

			if (err != nil) != test.expErr {
				t.Errorf("unexpected error, exp=%t got=%v", test.expErr, err)
			}

			if !reflect.DeepEqual(gid, test.expGID) {
				t.Errorf("unexpected gid, exp=%v got=%v", test.expGID, gid)
			}
		})
	}
}

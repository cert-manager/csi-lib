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

package manager

import (
	"crypto"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	fakeclock "k8s.io/utils/clock/testing"

	"github.com/cert-manager/csi-lib/metadata"
	"github.com/cert-manager/csi-lib/storage"
	testutil "github.com/cert-manager/csi-lib/test/util"
)

func TestManager_StoreVolumeSecrets(t *testing.T) {
	opts := newDefaultTestOptions(t)
	m, err := NewManager(opts)
	require.NoError(t, err)
	defer m.Stop()

	secrets := map[string]string{"pkcs12-password": "test-pass", "other-key": "other-value"}
	m.StoreVolumeSecrets("vol-id", secrets)

	m.volumeSecretsLock.Lock()
	got := m.volumeSecrets["vol-id"]
	m.volumeSecretsLock.Unlock()

	assert.Equal(t, secrets, got)
}

func TestManager_StoreVolumeSecrets_overwritesPreviousSecrets(t *testing.T) {
	opts := newDefaultTestOptions(t)
	m, err := NewManager(opts)
	require.NoError(t, err)
	defer m.Stop()

	m.StoreVolumeSecrets("vol-id", map[string]string{"key": "old-value"})
	m.StoreVolumeSecrets("vol-id", map[string]string{"key": "new-value"})

	m.volumeSecretsLock.Lock()
	got := m.volumeSecrets["vol-id"]
	m.volumeSecretsLock.Unlock()

	assert.Equal(t, map[string]string{"key": "new-value"}, got)
}

func TestManager_UnmanageVolume_cleansUpSecrets(t *testing.T) {
	opts := newDefaultTestOptions(t)
	m, err := NewManager(opts)
	require.NoError(t, err)

	store := opts.MetadataReader.(storage.Interface)
	meta := metadata.Metadata{VolumeID: "vol-id", TargetPath: "/fake/path"}
	_, err = store.RegisterMetadata(meta)
	require.NoError(t, err)
	defer store.RemoveVolume(meta.VolumeID)

	m.StoreVolumeSecrets("vol-id", map[string]string{"pkcs12-password": "test-pass"})
	m.ManageVolume("vol-id")
	m.UnmanageVolume("vol-id")

	m.volumeSecretsLock.Lock()
	_, exists := m.volumeSecrets["vol-id"]
	m.volumeSecretsLock.Unlock()

	assert.False(t, exists, "secrets should be cleaned up after UnmanageVolume")
}

func TestManager_SecretsInjectedIntoCallbacks(t *testing.T) {
	ctx := t.Context()

	var capturedSecrets map[string]string

	store := storage.NewMemoryFS()
	clk := fakeclock.NewFakeClock(time.Now())

	opts := defaultTestOptions(t, Options{
		MetadataReader: store,
		Clock:          clk,
		WriteKeypair: func(meta metadata.Metadata, key crypto.PrivateKey, chain []byte, ca []byte) error {
			capturedSecrets = meta.Secrets
			store.WriteFiles(meta, map[string][]byte{"ca": ca, "cert": chain})
			nextIssuanceTime := clk.Now().Add(time.Hour)
			meta.NextIssuanceTime = &nextIssuanceTime
			return store.WriteMetadata(meta.VolumeID, meta)
		},
	})

	m, err := NewManager(opts)
	require.NoError(t, err)
	defer m.Stop()

	go testutil.IssueOneRequest(ctx, t, opts.Client, defaultTestNamespace, selfSignedExampleCertificate, []byte("ca bytes"))

	meta := metadata.Metadata{VolumeID: "vol-id", TargetPath: "/fake/path"}
	_, err = store.RegisterMetadata(meta)
	require.NoError(t, err)
	defer func() {
		store.RemoveVolume(meta.VolumeID)
		m.UnmanageVolume(meta.VolumeID)
	}()

	secrets := map[string]string{"pkcs12-password": "test-pass"}
	m.StoreVolumeSecrets(meta.VolumeID, secrets)

	_, err = m.ManageVolumeImmediate(ctx, meta.VolumeID)
	require.NoError(t, err)

	assert.Equal(t, secrets, capturedSecrets)
}

func TestManager_SecretsNotInjectedAfterUnmanage(t *testing.T) {
	ctx := t.Context()

	var writeKeypairCallCount int

	store := storage.NewMemoryFS()
	clk := fakeclock.NewFakeClock(time.Now())

	opts := defaultTestOptions(t, Options{
		MetadataReader: store,
		Clock:          clk,
		WriteKeypair: func(meta metadata.Metadata, key crypto.PrivateKey, chain []byte, ca []byte) error {
			writeKeypairCallCount++
			store.WriteFiles(meta, map[string][]byte{"ca": ca, "cert": chain})
			nextIssuanceTime := clk.Now().Add(time.Hour)
			meta.NextIssuanceTime = &nextIssuanceTime
			return store.WriteMetadata(meta.VolumeID, meta)
		},
		GenerateRequest: func(meta metadata.Metadata) (*CertificateRequestBundle, error) {
			return &CertificateRequestBundle{Namespace: defaultTestNamespace}, nil
		},
		SignRequest: func(meta metadata.Metadata, key crypto.PrivateKey, req *x509.CertificateRequest) ([]byte, error) {
			return []byte{}, nil
		},
	})

	m, err := NewManager(opts)
	require.NoError(t, err)
	defer m.Stop()

	go testutil.IssueOneRequest(ctx, t, opts.Client, defaultTestNamespace, selfSignedExampleCertificate, []byte("ca bytes"))

	meta := metadata.Metadata{VolumeID: "vol-id", TargetPath: "/fake/path"}
	_, err = store.RegisterMetadata(meta)
	require.NoError(t, err)
	defer store.RemoveVolume(meta.VolumeID)

	m.StoreVolumeSecrets(meta.VolumeID, map[string]string{"pkcs12-password": "test-pass"})
	_, err = m.ManageVolumeImmediate(ctx, meta.VolumeID)
	require.NoError(t, err)

	m.UnmanageVolume(meta.VolumeID)

	m.volumeSecretsLock.Lock()
	_, exists := m.volumeSecrets[meta.VolumeID]
	m.volumeSecretsLock.Unlock()

	assert.False(t, exists, "secrets should not exist after UnmanageVolume")
	assert.Equal(t, 1, writeKeypairCallCount, "WriteKeypair should have been called exactly once")
}

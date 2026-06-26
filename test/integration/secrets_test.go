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

package integration

import (
	"crypto"
	"crypto/x509"
	"os"
	"testing"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	fakeclock "k8s.io/utils/clock/testing"

	"github.com/cert-manager/csi-lib/manager"
	"github.com/cert-manager/csi-lib/metadata"
	"github.com/cert-manager/csi-lib/storage"
	testdriver "github.com/cert-manager/csi-lib/test/driver"
	testutil "github.com/cert-manager/csi-lib/test/util"
)

func TestNodePublishVolume_secretsAvailableInCallbacks(t *testing.T) {
	ctx := t.Context()

	var capturedSecrets map[string]string

	store := storage.NewMemoryFS()
	clock := fakeclock.NewFakeClock(time.Now())

	opts, cl, stop := testdriver.Run(t, testdriver.Options{
		Store: store,
		Clock: clock,
		GeneratePrivateKey: func(_ metadata.Metadata) (crypto.PrivateKey, error) {
			return nil, nil
		},
		GenerateRequest: func(_ metadata.Metadata) (*manager.CertificateRequestBundle, error) {
			return &manager.CertificateRequestBundle{Namespace: "certificaterequest-namespace"}, nil
		},
		SignRequest: func(_ metadata.Metadata, _ crypto.PrivateKey, _ *x509.CertificateRequest) ([]byte, error) {
			return []byte{}, nil
		},
		WriteKeypair: func(meta metadata.Metadata, _ crypto.PrivateKey, chain []byte, ca []byte) error {
			capturedSecrets = meta.Secrets
			store.WriteFiles(meta, map[string][]byte{"ca": ca, "cert": chain})
			nextIssuanceTime := clock.Now().Add(time.Hour)
			meta.NextIssuanceTime = &nextIssuanceTime
			return store.WriteMetadata(meta.VolumeID, meta)
		},
	})
	defer stop()

	go testutil.IssueOneRequest(ctx, t, opts.Client, "certificaterequest-namespace", selfSignedExampleCertificate, []byte("ca bytes"))

	tmpDir, err := os.MkdirTemp("", "*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	secrets := map[string]string{"pkcs12-password": "my-secret-password"}

	_, err = cl.NodePublishVolume(ctx, &csi.NodePublishVolumeRequest{
		VolumeId: "test-vol",
		VolumeContext: map[string]string{
			"csi.storage.k8s.io/ephemeral":     "true",
			"csi.storage.k8s.io/pod.name":      "the-pod-name",
			"csi.storage.k8s.io/pod.namespace": "the-pod-namespace",
		},
		Secrets:    secrets,
		TargetPath: tmpDir,
		Readonly:   true,
	})
	require.NoError(t, err)

	assert.Equal(t, secrets, capturedSecrets)
}

func TestNodePublishVolume_noSecretsWhenRefNotSpecified(t *testing.T) {
	ctx := t.Context()

	var capturedSecrets map[string]string

	store := storage.NewMemoryFS()
	clock := fakeclock.NewFakeClock(time.Now())

	opts, cl, stop := testdriver.Run(t, testdriver.Options{
		Store: store,
		Clock: clock,
		GeneratePrivateKey: func(_ metadata.Metadata) (crypto.PrivateKey, error) {
			return nil, nil
		},
		GenerateRequest: func(_ metadata.Metadata) (*manager.CertificateRequestBundle, error) {
			return &manager.CertificateRequestBundle{Namespace: "certificaterequest-namespace"}, nil
		},
		SignRequest: func(_ metadata.Metadata, _ crypto.PrivateKey, _ *x509.CertificateRequest) ([]byte, error) {
			return []byte{}, nil
		},
		WriteKeypair: func(meta metadata.Metadata, _ crypto.PrivateKey, chain []byte, ca []byte) error {
			capturedSecrets = meta.Secrets
			store.WriteFiles(meta, map[string][]byte{"ca": ca, "cert": chain})
			nextIssuanceTime := clock.Now().Add(time.Hour)
			meta.NextIssuanceTime = &nextIssuanceTime
			return store.WriteMetadata(meta.VolumeID, meta)
		},
	})
	defer stop()

	go testutil.IssueOneRequest(ctx, t, opts.Client, "certificaterequest-namespace", selfSignedExampleCertificate, []byte("ca bytes"))

	tmpDir, err := os.MkdirTemp("", "*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	_, err = cl.NodePublishVolume(ctx, &csi.NodePublishVolumeRequest{
		VolumeId: "test-vol",
		VolumeContext: map[string]string{
			"csi.storage.k8s.io/ephemeral":     "true",
			"csi.storage.k8s.io/pod.name":      "the-pod-name",
			"csi.storage.k8s.io/pod.namespace": "the-pod-namespace",
		},
		TargetPath: tmpDir,
		Readonly:   true,
	})
	require.NoError(t, err)

	assert.Nil(t, capturedSecrets, "meta.Secrets should be nil when nodePublishSecretRef is not specified")
}

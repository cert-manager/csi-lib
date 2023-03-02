package manager

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"reflect"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/go-logr/logr/testr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/strings/slices"

	internalapi "github.com/cert-manager/csi-lib/internal/api"
	internalapiutil "github.com/cert-manager/csi-lib/internal/api/util"
	"github.com/cert-manager/csi-lib/metadata"
	"github.com/cert-manager/csi-lib/storage"
	testutil "github.com/cert-manager/csi-lib/test/util"
)

func TestManager_ManageVolumeImmediate_issueOnceAndSucceed(t *testing.T) {
	ctx := context.Background()

	opts := newDefaultTestOptions(t)
	m, err := NewManager(opts)
	if err != nil {
		t.Fatal(err)
	}

	// Setup a goroutine to issue one CertificateRequest
	stopCh := make(chan struct{})
	go testutil.IssueOneRequest(t, opts.Client, defaultTestNamespace, stopCh, selfSignedExampleCertificate, []byte("ca bytes"))
	defer close(stopCh)

	// Register a new volume with the metadata store
	store := opts.MetadataReader.(storage.Interface)
	meta := metadata.Metadata{
		VolumeID:   "vol-id",
		TargetPath: "/fake/path",
	}
	store.RegisterMetadata(meta)
	// Ensure we stop managing the volume after the test
	defer func() {
		store.RemoveVolume(meta.VolumeID)
		m.UnmanageVolume(meta.VolumeID)
	}()

	// Attempt to issue the certificate & put it under management
	managed, err := m.ManageVolumeImmediate(ctx, meta.VolumeID)
	if !managed {
		t.Errorf("expected management to have started, but it did not")
	}
	if err != nil {
		t.Errorf("expected no error from ManageVolumeImmediate but got: %v", err)
	}

	// Assert the certificate is under management
	if !m.IsVolumeReady(meta.VolumeID) {
		t.Errorf("expected volume to be marked as Ready but it is not")
	}
}

func TestManager_PropagatesRequestConditionMessages(t *testing.T) {
	tests := []struct {
		approved      string
		ready         string
		expectedError string
	}{
		{
			approved:      "",
			ready:         "",
			expectedError: "waiting for request: request \"certificaterequest-name\" has not yet been approved by approval plugin",
		},
		{
			approved:      "",
			ready:         "pending",
			expectedError: "waiting for request: request \"certificaterequest-name\" has not yet been approved by approval plugin",
		},
		{
			approved:      "",
			ready:         "failed",
			expectedError: "waiting for request: request \"certificaterequest-name\" has failed: failed",
		},
		//"pending approval, ready == true": {}
		{
			approved:      "denied",
			ready:         "",
			expectedError: "waiting for request: request \"certificaterequest-name\" has been denied by the approval plugin: denied",
		},
		{
			approved:      "denied",
			ready:         "pending",
			expectedError: "waiting for request: request \"certificaterequest-name\" has been denied by the approval plugin: denied",
		},
		{
			approved:      "denied",
			ready:         "failed",
			expectedError: "waiting for request: request \"certificaterequest-name\" has been denied by the approval plugin: denied",
		},
		//"denied, ready == true": {},
		{
			approved:      "approved",
			ready:         "",
			expectedError: "waiting for request: request \"certificaterequest-name\" has no ready condition",
		},
		{
			approved:      "approved",
			ready:         "pending",
			expectedError: "waiting for request: request \"certificaterequest-name\" is pending: pending",
		},
		{
			approved:      "approved",
			ready:         "failed",
			expectedError: "waiting for request: request \"certificaterequest-name\" has failed: failed",
		},
		//"approved, ready == true": {},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("approval=%q, readiness=%q", test.approved, test.ready), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
			defer cancel()

			opts := newDefaultTestOptions(t)
			m, err := NewManager(opts)
			if err != nil {
				t.Fatal(err)
			}
			defer m.Stop()
			m.requestNameGenerator = func() string { return "certificaterequest-name" }

			// build conditions to set based on test configuration
			var conditions []cmapi.CertificateRequestCondition
			switch test.approved {
			case "":
			case "approved":
				conditions = append(conditions, cmapi.CertificateRequestCondition{Type: cmapi.CertificateRequestConditionApproved, Status: cmmeta.ConditionTrue, Reason: "SetByTest", Message: "approved"})
			case "denied":
				conditions = append(conditions, cmapi.CertificateRequestCondition{Type: cmapi.CertificateRequestConditionDenied, Status: cmmeta.ConditionTrue, Reason: "SetByTest", Message: "denied"})
			}
			switch test.ready {
			case "":
			case "pending":
				conditions = append(conditions, cmapi.CertificateRequestCondition{Type: cmapi.CertificateRequestConditionReady, Status: cmmeta.ConditionFalse, Reason: cmapi.CertificateRequestReasonPending, Message: "pending"})
			case "failed":
				conditions = append(conditions, cmapi.CertificateRequestCondition{Type: cmapi.CertificateRequestConditionReady, Status: cmmeta.ConditionFalse, Reason: cmapi.CertificateRequestReasonFailed, Message: "failed"})
			}
			// Automatically set the request to be approved & pending once created
			go testutil.SetCertificateRequestConditions(ctx, t, opts.Client, defaultTestNamespace, conditions...)

			// Register a new volume with the metadata store
			store := opts.MetadataReader.(storage.Interface)
			meta := metadata.Metadata{
				VolumeID:   "vol-id",
				TargetPath: "/fake/path",
			}
			store.RegisterMetadata(meta)
			// Ensure we stop managing the volume after the test
			defer func() {
				store.RemoveVolume(meta.VolumeID)
				m.UnmanageVolume(meta.VolumeID)
			}()

			// Attempt to issue the certificate & put it under management
			managed, err := m.ManageVolumeImmediate(ctx, meta.VolumeID)
			if !managed {
				t.Errorf("expected volume to still be managed after failure")
			}
			if err == nil {
				t.Errorf("expected to get an error from ManageVolumeImmediate")
			}
			if err.Error() != test.expectedError {
				t.Errorf("expected '%s' but got: %s", test.expectedError, err.Error())
			}
		})
	}
}

func TestManager_ResumesManagementOfExistingVolumes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	store := storage.NewMemoryFS()
	opts := defaultTestOptions(t, Options{MetadataReader: store})

	m, err := NewManager(opts)
	if err != nil {
		t.Fatal(err)
	}

	m.requestNameGenerator = func() string { return "certificaterequest-name" }
	// Automatically issue the request once created
	go testutil.IssueOneRequest(t, opts.Client, defaultTestNamespace, ctx.Done(), selfSignedExampleCertificate, []byte("ca bytes"))

	// Register a new volume with the metadata store
	meta := metadata.Metadata{
		VolumeID:   "vol-id",
		TargetPath: "/fake/path",
	}
	_, err = store.RegisterMetadata(meta)
	if err != nil {
		t.Fatal(err)
	}

	// Attempt to issue the certificate & put it under management
	managed, err := m.ManageVolumeImmediate(ctx, meta.VolumeID)
	if !managed {
		t.Fatalf("expected volume to be managed")
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Shutdown the manager
	m.Stop()

	m, err = NewManager(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	if !m.IsVolumeReady(meta.VolumeID) {
		t.Errorf("expected volume to be monitored & ready but it is not")
	}
}

func TestManager_ManageVolume_beginsManagingAndProceedsIfNotReady(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	opts := newDefaultTestOptions(t)
	m, err := NewManager(opts)
	if err != nil {
		t.Fatal(err)
	}

	// Register a new volume with the metadata store
	store := opts.MetadataReader.(storage.Interface)
	meta := metadata.Metadata{
		VolumeID:   "vol-id",
		TargetPath: "/fake/path",
	}
	store.RegisterMetadata(meta)
	// Ensure we stop managing the volume after the test
	defer func() {
		store.RemoveVolume(meta.VolumeID)
		m.UnmanageVolume(meta.VolumeID)
	}()

	// Put the certificate under management
	managed := m.ManageVolume(meta.VolumeID)
	if !managed {
		t.Errorf("expected management to have started, but it did not")
	}

	if err := wait.PollUntilWithContext(ctx, time.Millisecond*500, func(ctx context.Context) (done bool, err error) {
		reqs, err := opts.Client.CertmanagerV1().CertificateRequests("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, err
		}
		if len(reqs.Items) == 1 {
			return true, nil
		}
		return false, nil
	}); err != nil {
		t.Errorf("failed waiting for CertificateRequest to exist: %v", err)
	}

	// Assert the certificate is under management - it won't be ready as no issuer has issued the certificate
	if m.IsVolumeReady(meta.VolumeID) {
		t.Errorf("expected volume to not be Ready but it is")
	}
	if _, ok := m.managedVolumes[meta.VolumeID]; !ok {
		t.Errorf("expected volume to be part of managedVolumes map but it is not")
	}
}

func TestManager_cleanupStaleRequests(t *testing.T) {
	type fields struct {
		nodeID               string
		maxRequestsPerVolume int
	}
	tests := []struct {
		name        string
		objects     []*cmapi.CertificateRequest
		toBeDeleted []string
		fields      fields
		wantErr     bool
	}{
		{
			name: "maxRequestsPerVolume=1: all stale CSRs should be deleted",
			objects: []*cmapi.CertificateRequest{
				cr("cr-1", defaultTestNamespace, "nodeID-1", "volumeID-1"),
				cr("cr-2", defaultTestNamespace, "nodeID-1", "volumeID-1"),
			},
			toBeDeleted: []string{"cr-2", "cr-1"},
			fields: fields{
				nodeID:               "nodeID-1",
				maxRequestsPerVolume: 1,
			},
			wantErr: false,
		},
		{
			name: "maxRequestsPerVolume=2: 1 stale CSRs should be left",
			objects: []*cmapi.CertificateRequest{
				cr("cr-1", defaultTestNamespace, "nodeID-1", "volumeID-1"),
				cr("cr-2", defaultTestNamespace, "nodeID-1", "volumeID-1"),
			},
			toBeDeleted: []string{"cr-2"},
			fields: fields{
				nodeID:               "nodeID-1",
				maxRequestsPerVolume: 2,
			},
			wantErr: false,
		},
		{
			name: "maxRequestsPerVolume=1: unrelated CSRs should NOT be deleted",
			objects: []*cmapi.CertificateRequest{
				cr("cr-1", defaultTestNamespace, "nodeID-1", "volumeID-2"),
				cr("cr-2", defaultTestNamespace, "nodeID-1", "volumeID-2"),
			},
			fields: fields{
				nodeID:               "nodeID-1",
				maxRequestsPerVolume: 1,
			},
			wantErr: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()
			log := testr.New(t)

			opts := newDefaultTestOptions(t)
			opts.MaxRequestsPerVolume = test.fields.maxRequestsPerVolume
			opts.NodeID = test.fields.nodeID
			m, err := NewManager(opts)
			if err != nil {
				t.Fatal(err)
			}
			defer m.Stop()

			for _, req := range test.objects {
				if _, err := m.client.CertmanagerV1().CertificateRequests(req.Namespace).Create(ctx, req, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
			}

			// make sure client cache is in sync
			if err := wait.PollUntilWithContext(ctx, 5*time.Millisecond, func(context.Context) (done bool, err error) {
				list, err := m.client.CertmanagerV1().CertificateRequests(defaultTestNamespace).List(ctx, metav1.ListOptions{})
				if err != nil {
					return false, err
				}
				return len(list.Items) == len(test.objects), nil // poll until all objects are cached
			}); err != nil {
				t.Fatal(err)
			}

			if err := m.cleanupStaleRequests(ctx, log, "volumeID-1"); (err != nil) != test.wantErr {
				t.Errorf("cleanupStaleRequests() error = %v, wantErr %v", err, test.wantErr)
			}

			for _, req := range test.objects {
				_, err := m.client.CertmanagerV1().CertificateRequests(req.Namespace).Get(ctx, req.Name, metav1.GetOptions{})
				if err != nil && !apierrors.IsNotFound(err) {
					t.Fatal(err)
				}
				exists := !apierrors.IsNotFound(err)
				shouldExist := !slices.Contains(test.toBeDeleted, req.Name)
				if exists && !shouldExist {
					t.Errorf("expected %q to be deleted but it was not", req.Name)
				}
				if !exists && shouldExist {
					t.Errorf("expected %q to exist but it does not", req.Name)
				}
			}
		})
	}
}

func Test_calculateNextIssuanceTime(t *testing.T) {
	notBefore := time.Date(1970, time.January, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(1970, time.January, 4, 0, 0, 0, 0, time.UTC)
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber:          new(big.Int).Lsh(big.NewInt(1), 128),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &pk.PublicKey, pk)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	tests := map[string]struct {
		expTime time.Time
		expErr  bool
	}{
		"if no attributes given, return 2/3rd certificate lifetime": {
			expTime: notBefore.AddDate(0, 0, 2),
			expErr:  false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			renewTime, err := calculateNextIssuanceTime(certPEM)
			assert.Equal(t, test.expErr, err != nil)
			assert.Equal(t, test.expTime, renewTime)
		})
	}
}

func TestManager_issue_reuseLastPendingRequest(t *testing.T) {
	// ----- Setup -----
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	opts := newDefaultTestOptions(t)
	opts.GeneratePrivateKey = func(meta metadata.Metadata) (crypto.PrivateKey, error) {
		return pki.GenerateECPrivateKey(256) // generate an EC-P-256 private key
	}
	opts.GenerateRequest = func(meta metadata.Metadata) (*CertificateRequestBundle, error) {
		// generate a CSR bundle in defaultTestNamespace, and its CN is specified in meta.VolumeContext["CN"] field
		return &CertificateRequestBundle{
			Namespace: defaultTestNamespace,
			Request: &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: meta.VolumeContext["CN"],
				},
			},
		}, nil
	}
	opts.SignRequest = func(meta metadata.Metadata, key crypto.PrivateKey, request *x509.CertificateRequest) ([]byte, error) {
		// sign the request with given private key, ignore the metadata
		csrDer, err := x509.CreateCertificateRequest(rand.Reader, request, key)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrDer,
		}), nil
	}

	m, err := NewManager(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	// Register a new volume with the metadata store
	store := opts.MetadataReader.(storage.Interface)
	meta := metadata.Metadata{
		VolumeID:   "vol-id",
		TargetPath: "/fake/path",
		VolumeContext: map[string]string{
			"CN": "test-cn-1",
		},
	}
	store.RegisterMetadata(meta)
	// Ensure we stop managing the volume after the test
	defer func() {
		store.RemoveVolume(meta.VolumeID)
		m.UnmanageVolume(meta.VolumeID)
	}()

	// ----- Test -----
	// Step 1: initial issuance should be timeout as we don't have an issuer
	err = m.issue(ctx, meta.VolumeID)
	if err == nil {
		t.Errorf("expect error from timeout, but got <nil> error")
	}
	reqList1, err := m.client.CertmanagerV1().CertificateRequests(defaultTestNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(reqList1.Items) != 1 {
		t.Errorf("expect 1 pending request, but got %d", len(reqList1.Items))
	}

	// Step 2: retry issuance should reuse the pending certificate
	err = m.issue(ctx, meta.VolumeID)
	if err == nil {
		t.Errorf("expect error from timeout, but got <nil> error")
	}
	reqList2, err := m.client.CertmanagerV1().CertificateRequests(defaultTestNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(reqList2.Items) != 1 {
		t.Errorf("expect 1 pending request, but got %d", len(reqList2.Items))
	}
	if !reflect.DeepEqual(reqList1.Items[0], reqList2.Items[0]) {
		t.Errorf("expect reuse pending rquest, but got a different one")
	}

	// Step 3: retry issuance with a different setting should create a new pending certificate
	meta.VolumeContext["CN"] = "test-cn-2"
	store.WriteMetadata(meta.VolumeID, meta)
	err = m.issue(ctx, meta.VolumeID)
	if err == nil {
		t.Errorf("expect error from timeout, but got <nil> error")
	}
	reqList3, err := m.client.CertmanagerV1().CertificateRequests(defaultTestNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(reqList3.Items) != 1 {
		t.Errorf("expect 1 pending request, but got %d", len(reqList3.Items))
	}
	if reflect.DeepEqual(reqList2.Items[0], reqList3.Items[0]) {
		t.Errorf("expect creating a new pending rquest, but got the same one")
	}
}

func cr(crName, crNamespace, nodeID, volumeID string) *cmapi.CertificateRequest {
	return &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      crName,
			Namespace: crNamespace,
			Labels: map[string]string{
				internalapi.NodeIDHashLabelKey:   internalapiutil.HashIdentifier(nodeID),
				internalapi.VolumeIDHashLabelKey: internalapiutil.HashIdentifier(volumeID),
			},
		}}
}

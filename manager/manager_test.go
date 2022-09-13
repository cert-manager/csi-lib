package manager

import (
	"context"
	"fmt"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/go-logr/logr/testr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	coretesting "k8s.io/client-go/testing"

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

	ctx := context.TODO()
	log := testr.New(t)

	type fields struct {
		nodeNameHash         string
		maxRequestsPerVolume int
	}

	tests := []struct {
		name     string
		builder  *testpkg.Builder
		fields   fields
		volumeID string
		wantErr  bool
	}{
		{
			name: "maxRequestsPerVolume=1: all stale CSRs should be deleted",
			builder: &testpkg.Builder{
				T: t,

				CertManagerObjects: []runtime.Object{
					cr("cr-1", "ns-1", "nodeNameHash-1", "volumeID-1"),
					cr("cr-2", "ns-1", "nodeNameHash-1", "volumeID-1"),
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewDeleteAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"ns-1", "cr-2")),
					testpkg.NewAction(coretesting.NewDeleteAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"ns-1", "cr-1")),
				},
			},
			fields: fields{
				nodeNameHash:         "nodeNameHash-1",
				maxRequestsPerVolume: 1,
			},
			volumeID: "volumeID-1",
			wantErr:  false,
		},
		{
			name: "maxRequestsPerVolume=2: 1 stale CSRs should be left",
			builder: &testpkg.Builder{
				T: t,

				CertManagerObjects: []runtime.Object{
					cr("cr-1", "ns-1", "nodeNameHash-1", "volumeID-1"),
					cr("cr-2", "ns-1", "nodeNameHash-1", "volumeID-1"),
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewDeleteAction(
						cmapi.SchemeGroupVersion.WithResource("certificaterequests"),
						"ns-1", "cr-2")),
				},
			},
			fields: fields{
				nodeNameHash:         "nodeNameHash-1",
				maxRequestsPerVolume: 2,
			},
			volumeID: "volumeID-1",
			wantErr:  false,
		},
		{
			name: "maxRequestsPerVolume=1: unrelated CSRs should NOT be deleted",
			builder: &testpkg.Builder{
				T: t,

				CertManagerObjects: []runtime.Object{
					cr("cr-1", "ns-1", "nodeNameHash-1", "volumeID-2"),
					cr("cr-2", "ns-1", "nodeNameHash-1", "volumeID-2"),
				},
				ExpectedActions: []testpkg.Action{},
			},
			fields: fields{
				nodeNameHash:         "nodeNameHash-1",
				maxRequestsPerVolume: 1,
			},
			volumeID: "volumeID-1",
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.builder.Init()
			cmClient := tt.builder.CMClient
			crLister := tt.builder.SharedInformerFactory.Certmanager().V1().CertificateRequests().Lister()

			tt.builder.Start()
			defer tt.builder.CheckAndFinish()

			m := &Manager{
				client:               cmClient,
				lister:               crLister,
				nodeNameHash:         tt.fields.nodeNameHash,
				maxRequestsPerVolume: tt.fields.maxRequestsPerVolume,
			}
			if err := m.cleanupStaleRequests(ctx, log, tt.volumeID); (err != nil) != tt.wantErr {
				t.Errorf("cleanupStaleRequests() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func cr(crName, crNamespace, nodeNameHash, VolumeID string) *cmapi.CertificateRequest {
	return &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      crName,
			Namespace: crNamespace,
			Labels: map[string]string{
				internalapi.NodeIDHashLabelKey:   nodeNameHash,
				internalapi.VolumeIDHashLabelKey: internalapiutil.HashIdentifier(VolumeID),
			},
		}}
}

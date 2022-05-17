package manager

import (
	"context"
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	logrtesting "github.com/go-logr/logr/testing"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"

	internalapi "github.com/cert-manager/csi-lib/internal/api"
	internalapiutil "github.com/cert-manager/csi-lib/internal/api/util"
)

func TestManager_cleanupStaleRequests(t *testing.T) {

	ctx := context.TODO()
	log := logrtesting.NewTestLogger(t)

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

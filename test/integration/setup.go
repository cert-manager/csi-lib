package integration

import (
	"context"
	"fmt"
	"github.com/go-logr/logr"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"google.golang.org/grpc"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/mount-utils"
	"net"
	"testing"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"k8s.io/utils/clock"

	fakeclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/fake"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1"
	"github.com/cert-manager/csi-lib/driver"
	"github.com/cert-manager/csi-lib/manager"
	"github.com/cert-manager/csi-lib/storage"
	testlogr "github.com/cert-manager/csi-lib/test/log"
)

type DriverOptions struct {
	Clock   clock.Clock
	Store   storage.Interface
	Log     logr.Logger
	Client  cmclient.CertmanagerV1Interface
	Mounter mount.Interface

	GeneratePrivateKey manager.GeneratePrivateKeyFunc
	GenerateRequest    manager.GenerateRequestFunc
	SignRequest        manager.SignRequestFunc
	WriteKeypair       manager.WriteKeypairFunc
}

func SetupTestDriver(t *testing.T, opts DriverOptions) (DriverOptions, csi.NodeClient, func()) {
	if opts.Log == nil {
		opts.Log = testlogr.TestLogger{T: t}
	}
	if opts.Clock == nil {
		opts.Clock = &clock.RealClock{}
	}
	if opts.Store == nil {
		opts.Store = storage.NewMemoryFS()
	}
	if opts.Client == nil {
		opts.Client = fakeclient.NewSimpleClientset().CertmanagerV1()
	}
	if opts.Mounter == nil {
		opts.Mounter = mount.NewFakeMounter(nil)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to setup test listener: %v", err)
	}

	m := manager.NewManagerOrDie(manager.Options{
		CertificateRequestClient: opts.Client,
		MetadataReader:           opts.Store,
		Clock:                    opts.Clock,
		Log:                      opts.Log,
		GeneratePrivateKey:       opts.GeneratePrivateKey,
		GenerateRequest:          opts.GenerateRequest,
		SignRequest:              opts.SignRequest,
		WriteKeypair:             opts.WriteKeypair,
	})

	d := driver.NewWithListener(lis, opts.Log, driver.Options{
		DriverName:    "driver-name",
		DriverVersion: "v0.0.1",
		NodeID:        "node-id",
		Store:         opts.Store,
		Mounter:       opts.Mounter,
		Manager:       m,
	})

	// start the driver
	go func() {
		if err := d.Run(); err != nil {
			t.Fatalf("failed running driver: %v", err)
		}
	}()

	// create a client connection to the grpc server
	conn, err := grpc.Dial(lis.Addr().String(), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("failed to dial test server: %v", err)
	}

	return opts, csi.NewNodeClient(conn), func() {
		m.Stop()
		if err := conn.Close(); err != nil {
			t.Fatalf("error closing client connection: %v", err)
		}
		d.Stop()
		lis.Close()
	}
}

func autoIssueOneRequest(t *testing.T, client cmclient.CertmanagerV1Interface, namespace string, stopCh <-chan struct{}, cert, ca []byte) {
	if err := wait.PollUntil(time.Millisecond*50, func() (done bool, err error) {
		reqs, err := client.CertificateRequests(namespace).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			return false, err
		}

		if len(reqs.Items) == 0 {
			return false, nil
		}
		if len(reqs.Items) > 1 {
			return false, fmt.Errorf("more than one CertificateRequest created")
		}

		req := reqs.Items[0]
		if len(req.Status.Certificate) != 0 {
			return false, fmt.Errorf("unexpected certificate already issued")
		}

		csr := req.DeepCopy()
		csr.Status.Conditions = append(req.Status.Conditions, cmapi.CertificateRequestCondition{
			Type:    cmapi.CertificateRequestConditionReady,
			Status:  cmmeta.ConditionTrue,
			Reason:  cmapi.CertificateRequestReasonIssued,
			Message: "Issued by test",
		})
		csr.Status.Certificate = cert
		csr.Status.CA = ca
		_, err = client.CertificateRequests(namespace).UpdateStatus(context.TODO(), csr, metav1.UpdateOptions{})
		if err != nil {
			return false, fmt.Errorf("error updating certificaterequest status: %v", err)
		}
		return true, nil
	}, stopCh); err != nil {
		t.Errorf("error automatically issuing certificaterequest: %v", err)
	}
}

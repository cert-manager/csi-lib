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
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	cminformers "github.com/jetstack/cert-manager/pkg/client/informers/externalversions"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/clock"

	"github.com/cert-manager/csi-lib/metadata"
	"github.com/cert-manager/csi-lib/storage"
)

// Options used to construct a Manager
type Options struct {
	// Client used to interact with the cert-manager API
	Client cmclient.Interface

	// Used the read metadata from the storage backend
	MetadataReader storage.MetadataReader

	// Clock used to determine when an issuance is due.
	// If not set, the RealClock implementation will be used.
	Clock clock.Clock

	// Logger used to write log messages
	Log logr.Logger

	GeneratePrivateKey GeneratePrivateKeyFunc
	GenerateRequest    GenerateRequestFunc
	SignRequest        SignRequestFunc
	WriteKeypair       WriteKeypairFunc
}

// NewManager constructs a new manager used to manage volumes containing
// certificate data.
// It will enumerate all volumes already persisted in the metadata store and
// resume managing them if any already exist.
func NewManager(opts Options) (*Manager, error) {
	if opts.Client == nil {
		return nil, errors.New("Client must be set")
	}
	if opts.Clock == nil {
		opts.Clock = clock.RealClock{}
	}
	if opts.Log == nil {
		return nil, errors.New("Log must be set")
	}
	if opts.MetadataReader == nil {
		return nil, errors.New("MetadataReader must be set")
	}
	if opts.GeneratePrivateKey == nil {
		return nil, errors.New("GeneratePrivateKey must be set")
	}
	if opts.GenerateRequest == nil {
		return nil, errors.New("GenerateRequest must be set")
	}
	if opts.SignRequest == nil {
		return nil, errors.New("SignRequest must be set")
	}
	if opts.WriteKeypair == nil {
		return nil, errors.New("WriteKeypair must be set")
	}

	// Create an informer factory
	informerFactory := cminformers.NewSharedInformerFactoryWithOptions(opts.Client, 0, cminformers.WithTweakListOptions(func(opts *metav1.ListOptions) {
		// TODO: filter informer
		opts.LabelSelector = ""
	}))
	// Fetch the lister before calling Start() to ensure this informer is
	// registered with the factory
	lister := informerFactory.Certmanager().V1().CertificateRequests().Lister()
	stopCh := make(chan struct{})
	// Begin watching the API
	informerFactory.Start(stopCh)
	informerFactory.WaitForCacheSync(stopCh)

	m := &Manager{
		client:         opts.Client,
		lister:         lister,
		metadataReader: opts.MetadataReader,
		clock:          opts.Clock,
		log:            opts.Log,

		generatePrivateKey: opts.GeneratePrivateKey,
		generateRequest:    opts.GenerateRequest,
		signRequest:        opts.SignRequest,
		writeKeypair:       opts.WriteKeypair,

		managedVolumes: map[string]chan struct{}{},
		stopInformer:   stopCh,
	}

	vols, err := opts.MetadataReader.ListVolumes()
	if err != nil {
		return nil, fmt.Errorf("listing existing volumes: %w", err)
	}

	for _, vol := range vols {
		m.log.Info("Registering existing data directory for management", "volume", vol)
		if err := m.ManageVolume(vol); err != nil {
			return nil, fmt.Errorf("loading existing volume: %w", err)
		}
	}

	return m, nil
}

func NewManagerOrDie(opts Options) *Manager {
	m, err := NewManager(opts)
	if err != nil {
		panic("failed to start manager: " + err.Error())
	}
	return m
}

// A Manager will manage key pairs in a storage backend.
// It is responsible for:
// * Generating private key data
// * Generating certificate requests (CSRs)
// * Submitting certificate requests
// * Waiting for requests to be completed
// * Persisting the keys back to the storage backend
//
// It also will trigger renewals of certificates when required.
type Manager struct {
	// client used to create & delete objects in the cert-manager API
	client cmclient.Interface

	// lister is used as a read-only cache of CertificateRequest resources
	lister cmlisters.CertificateRequestLister

	// used to read metadata from the store
	metadataReader storage.MetadataReader

	log   logr.Logger
	clock clock.Clock

	// User-configurable functions used to customise behaviour
	generatePrivateKey GeneratePrivateKeyFunc
	generateRequest    GenerateRequestFunc
	signRequest        SignRequestFunc
	writeKeypair       WriteKeypairFunc

	lock sync.Mutex
	// global view of all volumes managed by this manager
	// the stored channel is used to stop management of the
	// volume
	managedVolumes map[string]chan struct{}

	// Used to stop the informer watching for updates
	stopInformer chan struct{}
}

// issue will step through the entire issuance flow for a volume.
func (m *Manager) issue(volumeID string) error {
	ctx := context.TODO()
	log := m.log.WithValues("volume_id", volumeID)
	log.Info("Processing issuance")

	meta, err := m.metadataReader.ReadMetadata(volumeID)
	if err != nil {
		return fmt.Errorf("reading metadata: %w", err)
	}
	log.V(2).Info("Read metadata", "metadata", meta)

	key, err := m.generatePrivateKey(meta)
	if err != nil {
		return fmt.Errorf("generating private key: %w", err)
	}
	log.V(2).Info("Obtained new private key")

	csrBundle, err := m.generateRequest(meta)
	if err != nil {
		return fmt.Errorf("generating certificate signing request: %w", err)
	}
	log.V(2).Info("Constructed new CSR")

	csrDer, err := m.signRequest(meta, key, csrBundle.Request)
	if err != nil {
		return fmt.Errorf("signing certificate signing request: %w", err)
	}
	log.V(2).Info("Signed CSR")

	req, err := m.submitRequest(ctx, meta, csrBundle, csrDer)
	if err != nil {
		return fmt.Errorf("submitting request: %w", err)
	}
	log.Info("Created new CertificateRequest resource")

	// Poll every 1s for the CertificateRequest to be ready
	if err := wait.PollUntil(time.Second, func() (done bool, err error) {
		updatedReq, err := m.lister.CertificateRequests(req.Namespace).Get(req.Name)
		if apierrors.IsNotFound(err) {
			// A NotFound error implies something deleted the resource - fail
			// early to allow a retry to occur at a later time if needed.
			return false, err
		}
		if err != nil {
			log.Error(err, "Failed fetch CertificateRequest")
			// TODO: it'd probably be better to log transient errors and retry
			//       the Get to better handle cases where the apiserver is
			//       intermittently unavailable but otherwise the API works.
			return false, err
		}

		// Handle cases where the request has been explicitly denied
		if apiutil.CertificateRequestIsDenied(updatedReq) {
			cond := apiutil.GetCertificateRequestCondition(updatedReq, cmapi.CertificateRequestConditionDenied)
			return false, fmt.Errorf("request %q has been denied by the approval plugin: %s", updatedReq.Name, cond.Message)
		}

		readyCondition := apiutil.GetCertificateRequestCondition(updatedReq, cmapi.CertificateRequestConditionReady)
		if readyCondition == nil {
			log.V(2).Info("CertificateRequest is still pending")
			// Issuance is still pending
			return false, nil
		}

		switch readyCondition.Reason {
		case cmapi.CertificateRequestReasonIssued:
			break
		case cmapi.CertificateRequestReasonFailed:
			return false, fmt.Errorf("request %q has failed: %s", updatedReq.Name, readyCondition.Message)
		case cmapi.CertificateRequestReasonPending:
			log.V(2).Info("CertificateRequest is still pending")
			return false, nil
		default:
			log.Info("unrecognised state for Ready condition", "request_namespace", updatedReq.Namespace, "request_name", updatedReq.Name, "condition", *readyCondition)
			return false, nil
		}

		// if issuance is complete, set req to the updatedReq and continue to
		log.V(2).Info("CertificateRequest completed and issued successfully")
		// writing out signed certificate
		req = updatedReq
		return true, nil
	}, ctx.Done()); err != nil {
		return fmt.Errorf("waiting for request: %w", err)
	}

	if err := m.writeKeypair(meta, key, req.Status.Certificate, req.Status.CA); err != nil {
		return fmt.Errorf("writing keypair: %w", err)
	}
	log.V(2).Info("Wrote new keypair to storage")

	return nil
}

// submitRequest will create a CertificateRequest resource and return the
// created resource.
func (m *Manager) submitRequest(ctx context.Context, meta metadata.Metadata, csrBundle *CertificateRequestBundle, csrDer []byte) (*cmapi.CertificateRequest, error) {
	// encode the CSR DER in PEM format
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDer,
	})

	req := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:        string(uuid.NewUUID()),
			Namespace:   csrBundle.Namespace,
			Annotations: csrBundle.Annotations,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "core/v1",
					Kind:       "Pod",
					Name:       meta.VolumeContext["csi.storage.k8s.io/pod.name"],
					UID:        types.UID(meta.VolumeContext["csi.storage.k8s.io/pod.uid"]),
				},
			},
		},
		Spec: cmapi.CertificateRequestSpec{
			Request:   csrPEM,
			IssuerRef: csrBundle.IssuerRef,
			Duration:  &metav1.Duration{Duration: csrBundle.Duration},
			IsCA:      csrBundle.IsCA,
			Usages:    csrBundle.Usages,
		},
	}

	req, err := m.client.CertmanagerV1().CertificateRequests(csrBundle.Namespace).Create(ctx, req, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	// Wait to ensure the lister has observed the creation of the CertificateRequest
	// This ensures callers that read from the lister/cache do not enter a confused state
	// where the CertificateRequest does not exist after calling submitRequest due to
	// cache timing issues.
	wait.PollUntil(time.Millisecond*50, func() (bool, error) {
		_, err := m.lister.CertificateRequests(csrBundle.Namespace).Get(req.Name)
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return true, nil
	}, ctx.Done())

	return req, nil
}

// ManageVolume will initiate management of data for the given volumeID.
func (m *Manager) ManageVolume(volumeID string) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	log := m.log.WithValues("volume_id", volumeID)

	// if the volume is already managed, return early
	if _, ok := m.managedVolumes[volumeID]; ok {
		log.V(2).Info("Volume already registered for management")
		return nil
	}

	// construct a new channel used to stop management of the volume
	stopCh := make(chan struct{})
	m.managedVolumes[volumeID] = stopCh

	go func() {
		// check every volume once per second
		// TODO: optimise this to not check so often
		ticker := time.NewTicker(time.Second)
		for {
			select {
			case <-stopCh:
				// management of this volume has been stopped, exit the goroutine
				return
			case <-ticker.C:
				meta, err := m.metadataReader.ReadMetadata(volumeID)
				if err != nil {
					log.Error(err, "Failed to read metadata")
					continue
				}

				if meta.NextIssuanceTime == nil || m.clock.Now().After(*meta.NextIssuanceTime) {
					log.Info("Triggering new issuance")
					if err := m.issue(volumeID); err != nil {
						log.Error(err, "Failed to issue certificate")
						// retry the request in 1 second time
						// TODO: exponentially back-off
						continue
					}
				}
			}
		}
	}()

	return nil
}

func (m *Manager) UnmanageVolume(volumeID string) {
	m.lock.Lock()
	defer m.lock.Unlock()

	if stopCh, ok := m.managedVolumes[volumeID]; ok {
		close(stopCh)
		delete(m.managedVolumes, volumeID)
	}
}

func (m *Manager) IsVolumeReady(volumeID string) bool {
	meta, err := m.metadataReader.ReadMetadata(volumeID)
	if err != nil {
		m.log.Error(err, "failed to read metadata", "volume_id", volumeID)
		return false
	}

	if meta.NextIssuanceTime == nil || m.clock.Now().After(*meta.NextIssuanceTime) {
		return false
	}

	return true
}

// Stop will stop management of all managed volumes
func (m *Manager) Stop() {
	m.lock.Lock()
	defer m.lock.Unlock()
	close(m.stopInformer)
	for k, stopCh := range m.managedVolumes {
		close(stopCh)
		delete(m.managedVolumes, k)
	}
}

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
	"errors"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	cminformers "github.com/cert-manager/cert-manager/pkg/client/informers/externalversions"
	cmlisters "github.com/cert-manager/cert-manager/pkg/client/listers/certmanager/v1"
	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/clock"

	internalapi "github.com/cert-manager/csi-lib/internal/api"
	internalapiutil "github.com/cert-manager/csi-lib/internal/api/util"
	"github.com/cert-manager/csi-lib/metadata"
	"github.com/cert-manager/csi-lib/storage"
)

// Options used to construct a Manager
type Options struct {
	// Client is used to interact with the cert-manager API to list and delete
	// requests.
	Client cmclient.Interface

	// ClientForMetadataFunc is used for returning a client that is used for
	// creating cert-manager API objects given a volume's metadata. If nil,
	// Client will always be used.
	ClientForMetadata ClientForMetadataFunc

	// Used the read metadata from the storage backend
	MetadataReader storage.MetadataReader

	// Clock used to determine when an issuance is due.
	// If not set, the RealClock implementation will be used.
	Clock clock.Clock

	// Logger used to write log messages
	Log *logr.Logger

	// Maximum number of CertificateRequests that should exist for each
	// volume mounted into a pod.
	// If not set, this will be defaulted to 1.
	// When the number of CertificateRequests for a volume exceeds this limit,
	// requests will be deleted before any new ones are created.
	MaxRequestsPerVolume int

	// NodeID is a unique identifier for the node.
	NodeID string

	GeneratePrivateKey GeneratePrivateKeyFunc
	GenerateRequest    GenerateRequestFunc
	SignRequest        SignRequestFunc
	WriteKeypair       WriteKeypairFunc
	ReadyToRequest     ReadyToRequestFunc

	// RenewalBackoffConfig configures the exponential backoff applied to certificate renewal failures.
	RenewalBackoffConfig *wait.Backoff
}

// NewManager constructs a new manager used to manage volumes containing
// certificate data.
// It will enumerate all volumes already persisted in the metadata store and
// resume managing them if any already exist.
func NewManager(opts Options) (*Manager, error) {
	if opts.Client == nil {
		return nil, errors.New("Client must be set")
	}
	if opts.ClientForMetadata == nil {
		opts.ClientForMetadata = func(_ metadata.Metadata) (cmclient.Interface, error) {
			return opts.Client, nil
		}
	}
	if opts.Clock == nil {
		opts.Clock = clock.RealClock{}
	}
	if opts.RenewalBackoffConfig == nil {
		opts.RenewalBackoffConfig = &wait.Backoff{
			// the 'base' amount of time for the backoff
			Duration: time.Second * 30,
			// We multiply the 'duration' by 2.0 if the attempt fails/errors
			Factor: 2.0,
			// Add a jitter of +/- 0.5 of the 'duration'
			Jitter: 0.5,
			// 'Steps' controls what the maximum number of backoff attempts is before we
			// reset back to the 'base duration'. Set this to the MaxInt32, as we never want to
			// reset this unless we get a successful attempt.
			Steps: math.MaxInt32,
			// The maximum time between calls will be 5 minutes
			Cap: time.Minute * 5,
		}
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
	if opts.ReadyToRequest == nil {
		opts.ReadyToRequest = AlwaysReadyToRequest
	}
	if opts.MaxRequestsPerVolume == 0 {
		opts.MaxRequestsPerVolume = 1
	}
	if opts.MaxRequestsPerVolume < 0 {
		return nil, errors.New("MaxRequestsPerVolume cannot be less than zero")
	}
	if len(opts.NodeID) == 0 {
		return nil, errors.New("NodeID must be set")
	}
	nodeNameHash := internalapiutil.HashIdentifier(opts.NodeID)
	nodeNameReq, err := labels.NewRequirement(internalapi.NodeIDHashLabelKey, selection.Equals, []string{nodeNameHash})
	if err != nil {
		return nil, fmt.Errorf("building node name label selector: %w", err)
	}

	// Create an informer factory
	informerFactory := cminformers.NewSharedInformerFactoryWithOptions(opts.Client, 0, cminformers.WithTweakListOptions(func(opts *metav1.ListOptions) {
		opts.LabelSelector = labels.NewSelector().Add(*nodeNameReq).String()
	}))
	// Fetch the lister before calling Start() to ensure this informer is
	// registered with the factory
	lister := informerFactory.Certmanager().V1().CertificateRequests().Lister()
	stopCh := make(chan struct{})
	// Begin watching the API
	informerFactory.Start(stopCh)
	informerFactory.WaitForCacheSync(stopCh)

	m := &Manager{
		client:            opts.Client,
		clientForMetadata: opts.ClientForMetadata,
		lister:            lister,
		metadataReader:    opts.MetadataReader,
		clock:             opts.Clock,
		log:               *opts.Log,

		generatePrivateKey: opts.GeneratePrivateKey,
		generateRequest:    opts.GenerateRequest,
		signRequest:        opts.SignRequest,
		writeKeypair:       opts.WriteKeypair,
		readyToRequest:     opts.ReadyToRequest,

		managedVolumes: map[string]chan struct{}{},
		stopInformer:   stopCh,

		maxRequestsPerVolume: opts.MaxRequestsPerVolume,
		nodeNameHash:         nodeNameHash,
		backoffConfig:        *opts.RenewalBackoffConfig,
		requestNameGenerator: func() string {
			return string(uuid.NewUUID())
		},
	}

	vols, err := opts.MetadataReader.ListVolumes()
	if err != nil {
		return nil, fmt.Errorf("listing existing volumes: %w", err)
	}

	for _, vol := range vols {
		log := m.log.WithValues("volume_id", vol)
		meta, err := opts.MetadataReader.ReadMetadata(vol)
		if err != nil {
			// This implies something has modified the state store whilst we are starting up
			// return the error and hope that next time we startup, nothing else changes the filesystem
			return nil, fmt.Errorf("reading existing volume metadata: %w", err)
		}
		if meta.NextIssuanceTime == nil {
			// This implies that a successful issuance has never been completed for this volume.
			// don't register these volumes for management automatically as they could be leftover
			// from a previous instance of the CSI driver handling a NodePublishVolume call that was
			// not able to clean up the state store before an unexpected exit.
			// Whatever is calling the CSI plugin should call NodePublishVolume again relatively soon
			// after we start up, which will trigger management to resume.
			// Note: if continueOnNotReady is set to 'true', the metadata file will persist the nextIssuanceTime as the epoch time.
			//       We will therefore resume management of these volumes despite there not having been a successful initial issuance.
			//       For users upgrading from an older version of the csi-lib, this field will not be set.
			//       These pods will only have management begun again upon the next NodePublishVolume call, which
			//       may not happen at all unless `requireRepublish: true` is set on the CSIDriver object.
			// TODO: we should probably consider deleting the volume from the state store in these instances
			//       to avoid having leftover metadata files for pods that don't actually exist anymore.
			log.Info("Skipping management of volume that has never successfully completed")
			continue
		}
		log.Info("Registering existing data directory for management", "volume", vol)
		m.ManageVolume(vol)
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
	// client used to delete objects in the cert-manager API
	client cmclient.Interface

	// clientForMetadata used to create objects in the cert-manager API given a
	// volume's metadata
	clientForMetadata ClientForMetadataFunc

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
	readyToRequest     ReadyToRequestFunc

	lock sync.Mutex
	// global view of all volumes managed by this manager
	// the stored channel is used to stop management of the
	// volume
	managedVolumes map[string]chan struct{}

	// Used to stop the informer watching for updates
	stopInformer chan struct{}

	// hash of the node name this driver is running on, used to label CertificateRequest
	// resources to allow the lister to be scoped to requests for this node only
	nodeNameHash string

	// maximum number of CertificateRequests that should exist at any time for each volume
	maxRequestsPerVolume int

	// backoffConfig configures the exponential backoff applied to certificate renewal failures.
	backoffConfig wait.Backoff

	// requestNameGenerator generates a new random name for a certificaterequest object
	// Defaults to uuid.NewUUID() from k8s.io/apimachinery/pkg/util/uuid.
	requestNameGenerator func() string
}

// issue will step through the entire issuance flow for a volume.
func (m *Manager) issue(ctx context.Context, volumeID string) error {
	log := m.log.WithValues("volume_id", volumeID)
	log.Info("Processing issuance")

	if err := m.cleanupStaleRequests(ctx, log, volumeID); err != nil {
		return fmt.Errorf("cleaning up stale requests: %w", err)
	}

	meta, err := m.metadataReader.ReadMetadata(volumeID)
	if err != nil {
		return fmt.Errorf("reading metadata: %w", err)
	}
	log.V(2).Info("Read metadata", "metadata", meta)

	if ready, reason := m.readyToRequest(meta); !ready {
		return fmt.Errorf("driver is not ready to request a certificate for this volume: %v", reason)
	}

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

	csrPEM, err := m.signRequest(meta, key, csrBundle.Request)
	if err != nil {
		return fmt.Errorf("signing certificate signing request: %w", err)
	}
	log.V(2).Info("Signed CSR")

	req, err := m.submitRequest(ctx, meta, csrBundle, csrPEM)
	if err != nil {
		return fmt.Errorf("submitting request: %w", err)
	}
	log.Info("Created new CertificateRequest resource")

	// Poll every 1s for the CertificateRequest to be ready
	lastFailureReason := ""
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
			// if a CR has been explicitly denied, we DO stop execution.
			// there may be a case to be made that we could continue anyway even if the issuer ignores the approval
			// status, however these cases are likely few and far between and this makes denial more responsive.
			return false, fmt.Errorf("request %q has been denied by the approval plugin: %s", updatedReq.Name, cond.Message)
		}

		if !apiutil.CertificateRequestIsApproved(updatedReq) {
			lastFailureReason = "request has not yet been approved by approval plugin"
			// we don't stop execution here, as some versions of cert-manager (and some external issuer plugins)
			// may not be aware/utilise approval.
			// If the certificate is still issued despite never being approved, the CSI driver should continue
			// and use the issued certificate despite not being approved.
		}

		readyCondition := apiutil.GetCertificateRequestCondition(updatedReq, cmapi.CertificateRequestConditionReady)
		if readyCondition == nil {
			if apiutil.CertificateRequestIsApproved(updatedReq) {
				lastFailureReason = "request has no ready condition"
			}
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
			lastFailureReason = fmt.Sprintf("request pending: %v", readyCondition.Message)
			log.V(2).Info("CertificateRequest is still pending")
			return false, nil
		default:
			lastFailureReason = fmt.Sprintf("unrecognised Ready condition state (%s): %s", readyCondition.Reason, readyCondition.Message)
			log.Info("unrecognised state for Ready condition", "request_namespace", updatedReq.Namespace, "request_name", updatedReq.Name, "condition", *readyCondition)
			return false, nil
		}

		// if issuance is complete, set req to the updatedReq and continue to
		log.V(2).Info("CertificateRequest completed and issued successfully")
		// writing out signed certificate
		req = updatedReq
		return true, nil
	}, ctx.Done()); err != nil {
		if errors.Is(err, wait.ErrWaitTimeout) {
			// try and return a more helpful error message than "timed out waiting for the condition"
			return fmt.Errorf("waiting for request: %s", lastFailureReason)
		}
		return fmt.Errorf("waiting for request: %w", err)
	}

	if err := m.writeKeypair(meta, key, req.Status.Certificate, req.Status.CA); err != nil {
		return fmt.Errorf("writing keypair: %w", err)
	}
	log.V(2).Info("Wrote new keypair to storage")

	return nil
}

func (m *Manager) cleanupStaleRequests(ctx context.Context, log logr.Logger, volumeID string) error {
	sel, err := m.labelSelectorForVolume(volumeID)
	if err != nil {
		return fmt.Errorf("internal error building label selector - this is a bug, please open an issue: %w", err)
	}

	reqs, err := m.lister.List(sel)
	if err != nil {
		return fmt.Errorf("listing certificaterequests: %w", err)
	}

	if len(reqs) < m.maxRequestsPerVolume {
		return nil
	}

	// sort newest first to oldest last
	sort.Slice(reqs, func(i, j int) bool {
		return reqs[i].CreationTimestamp.After(reqs[j].CreationTimestamp.Time)
	})

	// start at the end of the slice and work back to maxRequestsPerVolume
	for i := len(reqs) - 1; i >= m.maxRequestsPerVolume-1; i-- {
		toDelete := reqs[i]
		if err := m.client.CertmanagerV1().CertificateRequests(toDelete.Namespace).Delete(ctx, toDelete.Name, metav1.DeleteOptions{}); err != nil {
			if apierrors.IsNotFound(err) {
				// don't fail if the resource is already deleted
			} else {
				return fmt.Errorf("deleting old certificaterequest: %w", err)
			}
		}

		log.Info("Deleted CertificateRequest resource", "name", toDelete.Name, "namespace", toDelete.Namespace)
	}

	return nil
}

func (m *Manager) labelSelectorForVolume(volumeID string) (labels.Selector, error) {
	sel := labels.NewSelector()
	req, err := labels.NewRequirement(internalapi.NodeIDHashLabelKey, selection.Equals, []string{m.nodeNameHash})
	if err != nil {
		return nil, err
	}
	sel = sel.Add(*req)
	req, err = labels.NewRequirement(internalapi.VolumeIDHashLabelKey, selection.Equals, []string{internalapiutil.HashIdentifier(volumeID)})
	if err != nil {
		return nil, err
	}
	sel = sel.Add(*req)
	return sel, nil
}

// submitRequest will create a CertificateRequest resource and return the
// created resource.
func (m *Manager) submitRequest(ctx context.Context, meta metadata.Metadata, csrBundle *CertificateRequestBundle, csrPEM []byte) (*cmapi.CertificateRequest, error) {
	req := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:        m.requestNameGenerator(),
			Namespace:   csrBundle.Namespace,
			Annotations: csrBundle.Annotations,
			Labels: map[string]string{
				internalapi.NodeIDHashLabelKey:   m.nodeNameHash,
				internalapi.VolumeIDHashLabelKey: internalapiutil.HashIdentifier(meta.VolumeID),
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "v1",
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

	createClient, err := m.clientForMetadata(meta)
	if err != nil {
		return nil, fmt.Errorf("failed to get create client for %q: %w", meta.VolumeID, err)
	}

	req, err = createClient.CertmanagerV1().CertificateRequests(csrBundle.Namespace).Create(ctx, req, metav1.CreateOptions{})
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

// ManageVolumeImmediate will register a volume for management and immediately attempt a single issuance.
// If issuing the initial certificate succeeds, the background renewal routine will be started similar to Manage().
// Upon failure, it is the caller's responsibility to explicitly call `UnmanageVolume`.
func (m *Manager) ManageVolumeImmediate(ctx context.Context, volumeID string) (managed bool, err error) {
	if !m.manageVolumeIfNotManaged(volumeID) {
		return false, nil
	}

	meta, err := m.metadataReader.ReadMetadata(volumeID)
	if err != nil {
		return true, fmt.Errorf("reading metadata: %w", err)
	}

	// Only attempt issuance immediately if there isn't already an issued certificate
	if meta.NextIssuanceTime == nil {
		// If issuance fails, immediately return without retrying so the caller can decide
		// how to proceed depending on the context this method was called within.
		if err := m.issue(ctx, volumeID); err != nil {
			return true, err
		}
	}

	if !m.startRenewalRoutine(volumeID) {
		return true, fmt.Errorf("unexpected state: renewal routine not started, please open an issue at https://github.com/cert-manager/csi-lib")
	}

	return true, nil
}

// manageVolumeIfNotManaged will ensure the named volume has been registered for management.
// It returns 'true' if the volume was not previously managed, and false if the volume was already managed.
func (m *Manager) manageVolumeIfNotManaged(volumeID string) (managed bool) {
	m.lock.Lock()
	defer m.lock.Unlock()
	log := m.log.WithValues("volume_id", volumeID)

	// if the volume is already managed, return early
	if _, managed := m.managedVolumes[volumeID]; managed {
		log.V(2).Info("Volume already registered for management")
		return false
	}

	// construct a new channel used to stop management of the volume
	stopCh := make(chan struct{})
	m.managedVolumes[volumeID] = stopCh

	return true
}

// startRenewalRoutine will begin the background issuance goroutine for the given volumeID.
// It is the caller's responsibility to ensure this is only called once per volume.
func (m *Manager) startRenewalRoutine(volumeID string) (started bool) {
	m.lock.Lock()
	defer m.lock.Unlock()
	log := m.log.WithValues("volume_id", volumeID)

	stopCh, ok := m.managedVolumes[volumeID]
	if !ok {
		log.Info("Volume not registered for management, cannot start renewal routine...")
		return false
	}

	// Create a context that will be cancelled when the stopCh is closed
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-stopCh:
			cancel()
		}
	}()

	go func() {
		// check every volume once per second
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
					// If issuing a certificate fails, we don't go around the outer for loop again (as we'd then be creating
					// a new CertificateRequest every second).
					// Instead, retry within the same iteration of the for loop and apply an exponential backoff.
					// Because we pass ctx through to the 'wait' package, if the stopCh is closed/context is cancelled,
					// we'll immediately stop waiting and 'continue' which will then hit the `case <-stopCh` case in the `select`.
					if err := wait.ExponentialBackoffWithContext(ctx, m.backoffConfig, func() (bool, error) {
						log.Info("Triggering new issuance")
						if err := m.issue(ctx, volumeID); err != nil {
							log.Error(err, "Failed to issue certificate, retrying after applying exponential backoff")
							return false, nil
						}
						return true, nil
					}); err != nil {
						if errors.Is(err, wait.ErrWaitTimeout) || errors.Is(err, context.DeadlineExceeded) {
							continue
						}
						// this should never happen as the function above never actually returns errors
						log.Error(err, "unexpected error")
					}
				}
			}
		}
	}()
	return true
}

// ManageVolume will initiate management of data for the given volumeID. It will not wait for an initial certificate
// to be issued and instead rely on the renewal handling loop to issue the initial certificate.
// Callers can use `IsVolumeReady` to determine if a certificate has been successfully issued or not.
// Upon failure, it is the callers responsibility to call `UnmanageVolume`.
func (m *Manager) ManageVolume(volumeID string) (managed bool) {
	log := m.log.WithValues("volume_id", volumeID)
	if managed := m.manageVolumeIfNotManaged(volumeID); !managed {
		return false
	}
	if started := m.startRenewalRoutine(volumeID); !started {
		log.Info("unexpected state: renewal routine not started, please open an issue at https://github.com/cert-manager/csi-lib")
	}
	return true
}

func (m *Manager) UnmanageVolume(volumeID string) {
	m.lock.Lock()
	defer m.lock.Unlock()

	if stopCh, ok := m.managedVolumes[volumeID]; ok {
		close(stopCh)
		delete(m.managedVolumes, volumeID)
	}
}

func (m *Manager) IsVolumeReadyToRequest(volumeID string) (bool, string) {
	meta, err := m.metadataReader.ReadMetadata(volumeID)
	if err != nil {
		m.log.Error(err, "failed to read metadata", "volume_id", volumeID)
		return false, ""
	}

	return m.readyToRequest(meta)
}

func (m *Manager) IsVolumeReady(volumeID string) bool {
	m.lock.Lock()
	defer m.lock.Unlock()
	// a volume is not classed as Ready if it is not managed
	if _, managed := m.managedVolumes[volumeID]; !managed {
		return false
	}

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

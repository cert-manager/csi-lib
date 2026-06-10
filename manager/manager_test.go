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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/go-logr/logr/testr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/strings/slices"

	internalapi "github.com/cert-manager/csi-lib/internal/api"
	internalapiutil "github.com/cert-manager/csi-lib/internal/api/util"
	"github.com/cert-manager/csi-lib/metadata"
	"github.com/cert-manager/csi-lib/metrics"
	"github.com/cert-manager/csi-lib/storage"
	testutil "github.com/cert-manager/csi-lib/test/util"
)

func TestManager_ManageVolumeImmediate_issueOnceAndSucceed(t *testing.T) {
	ctx := t.Context()

	opts := newDefaultTestOptions(t)
	m, err := NewManager(opts)
	if err != nil {
		t.Fatal(err)
	}

	// Setup a goroutine to issue one CertificateRequest
	go testutil.IssueOneRequest(ctx, t, opts.Client, defaultTestNamespace, selfSignedExampleCertificate, []byte("ca bytes"))

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
	go testutil.IssueOneRequest(ctx, t, opts.Client, defaultTestNamespace, selfSignedExampleCertificate, []byte("ca bytes"))

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
	ctx := t.Context()

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

	if err := wait.PollUntilContextCancel(ctx, time.Millisecond*500, true, func(ctx context.Context) (done bool, err error) {
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

func TestManager_ManageVolume_exponentialBackOffRetryOnIssueErrors(t *testing.T) {
	expBackOffDuration := 100 * time.Millisecond
	expBackOffCap := 5 * expBackOffDuration
	expBackOffFactor := 2.0 // We multiply the 'duration' by 2.0 if the attempt fails/errors
	expBackOffJitter := 0.0 // No jitter to the 'duration', so we could calculate number of retries easily
	expBackOffSteps := 100  // The maximum number of backoff attempts
	issueRenewalTimeout := expBackOffDuration

	// Expected number of retries in each expBackOff cycle :=
	// 				⌈log base expBackOffFactor of (expBackOffCap/expBackOffDuration)⌉
	var expectNumOfRetries float64 = 3 // ⌈log2(500/100)⌉

	// Because in startRenewalRoutine, ticker := time.NewTicker(time.Second)
	// 2 seconds should complete an expBackOff cycle
	// ticker start time (1s) + expBackOffCap (0.5s) + expectNumOfRetries (3) * issueRenewalTimeout (0.1)
	expectGlobalTimeout := 2 * time.Second

	opts := newDefaultTestOptions(t)
	opts.RenewalBackoffConfig = &wait.Backoff{
		Duration: expBackOffDuration,
		Cap:      expBackOffCap,
		Factor:   expBackOffFactor,
		Jitter:   expBackOffJitter,
		Steps:    expBackOffSteps,
	}

	// Create the manager first to get access to the lister
	m, err := NewManager(opts)
	if err != nil {
		t.Fatal(err)
	}
	m.issueRenewalTimeout = issueRenewalTimeout

	// Create metrics for the manager using the manager's lister
	log := testr.New(t)
	registry := prometheus.NewRegistry()
	store := opts.MetadataReader.(storage.Interface)
	metricsHandler := metrics.New(opts.NodeID, &log, registry, store, m.lister)

	// Update the manager's metrics
	m.metrics = metricsHandler

	// Register a new volume with the metadata store
	meta := metadata.Metadata{
		VolumeID:   "vol-id",
		TargetPath: "/fake/path",
	}
	if _, err := store.RegisterMetadata(meta); err != nil {
		t.Fatal(err)
	}
	// Ensure we stop managing the volume after the test
	defer func() {
		if err := store.RemoveVolume(meta.VolumeID); err != nil {
			t.Logf("failed to remove volume: %v", err)
		}
		m.UnmanageVolume(meta.VolumeID)
	}()

	// Put the certificate under management
	managed := m.ManageVolume(meta.VolumeID)
	if !managed {
		t.Errorf("expected management to have started, but it did not")
	}

	time.Sleep(expectGlobalTimeout)

	// Read the metric value from the registry
	// Gather all metrics and find the certmanager_csi_issue_requests_total metric
	metricFamilies, err := registry.Gather()
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}

	var actualNumOfRetries float64
	for _, mf := range metricFamilies {
		if mf.GetName() == "certmanager_csi_issue_requests_total" {
			// Get the first metric (there should only be one with our labels)
			if len(mf.GetMetric()) > 0 {
				actualNumOfRetries = mf.GetMetric()[0].GetCounter().GetValue()
			}
			break
		}
	}

	if actualNumOfRetries != expectNumOfRetries {
		t.Errorf("expect %g retries, but got %g", expectNumOfRetries, actualNumOfRetries)
	}
}

// TestManager_attemptIssuanceIfDue_backoffByErrorClass exercises the retry
// helper's selection between gateBackoffConfig (for ReadyToRequestFunc
// returning false) and RenewalBackoffConfig (for issuance errors). Each
// scenario scripts a sequence of per-issue() outcomes; the test asserts the
// helper completes within a deadline that would be exceeded if the wrong
// backoff were applied to the wrong error class.
//
// Calling attemptIssuanceIfDue directly avoids the renewal goroutine's 1-second
// ticker tax that an end-to-end ManageVolume test would pay, so each scenario
// runs in single-digit milliseconds. The integration path is already exercised
// by TestManager_ManageVolume_beginsManagingAndProceedsIfNotReady and
// TestManager_ManageVolume_exponentialBackOffRetryOnIssueErrors.
func TestManager_attemptIssuanceIfDue_backoffByErrorClass(t *testing.T) {
	type outcome int
	const (
		success outcome = iota
		notReady
		signFailure
	)

	const slow = 500 * time.Millisecond
	const fast = 1 * time.Millisecond

	tests := map[string]struct {
		// One entry per issue() call. Runs out → subsequent attempts succeed.
		script         []outcome
		renewalBackoff *wait.Backoff
		gateBackoff    *wait.Backoff
		// wantUnder is the wall-clock budget. Set so a misrouted backoff would
		// blow it (gate using renewalBackoff or vice versa).
		wantUnder time.Duration
	}{
		"gate-pending uses gate backoff not renewal backoff": {
			// 3 notReady × renewalBackoff would be ≥ 1.5s; gateBackoff makes it ≪100ms.
			script:         []outcome{notReady, notReady, notReady},
			renewalBackoff: &wait.Backoff{Duration: slow, Factor: 1.0, Steps: math.MaxInt32, Cap: slow},
			gateBackoff:    &wait.Backoff{Duration: fast, Factor: 1.0, Steps: math.MaxInt32, Cap: fast},
			wantUnder:      100 * time.Millisecond,
		},
		"issuance failure uses renewal backoff not gate backoff": {
			// 2 signFailure × gateBackoff would be ≥ 1s; renewalBackoff makes it ≪100ms.
			script:         []outcome{signFailure, signFailure},
			renewalBackoff: &wait.Backoff{Duration: fast, Factor: 1.0, Steps: math.MaxInt32, Cap: fast},
			gateBackoff:    &wait.Backoff{Duration: slow, Factor: 1.0, Steps: math.MaxInt32, Cap: slow},
			wantUnder:      100 * time.Millisecond,
		},
		"alternating classes do not bleed: gate-pending then signer error then gate-pending recovers": {
			// If either backoff failed to reset on class change, a later run of
			// the same class would inherit a grown delay and exceed the budget.
			script:         []outcome{notReady, notReady, signFailure, notReady, notReady},
			renewalBackoff: &wait.Backoff{Duration: fast, Factor: 1.0, Steps: math.MaxInt32, Cap: fast},
			gateBackoff:    &wait.Backoff{Duration: fast, Factor: 1.0, Steps: math.MaxInt32, Cap: fast},
			wantUnder:      100 * time.Millisecond,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// readyToRequest advances a shared per-issue() index; signRequest
			// reads the same index so both stubs agree on which scripted
			// outcome applies to the current issue() call.
			var idx int32 = -1
			readyToRequest := func(_ metadata.Metadata) (bool, string) {
				i := int(atomic.AddInt32(&idx, 1))
				if i < len(tc.script) && tc.script[i] == notReady {
					return false, "gate not yet met"
				}
				return true, ""
			}
			signRequest := func(_ metadata.Metadata, _ crypto.PrivateKey, _ *x509.CertificateRequest) ([]byte, error) {
				i := int(atomic.LoadInt32(&idx))
				if i < len(tc.script) && tc.script[i] == signFailure {
					return nil, fmt.Errorf("simulated signer error")
				}
				return nothingSignRequest(metadata.Metadata{}, nil, nil)
			}

			opts := newDefaultTestOptions(t)
			opts.ReadyToRequest = readyToRequest
			opts.SignRequest = signRequest
			opts.RenewalBackoffConfig = tc.renewalBackoff
			opts.GateBackoffConfig = tc.gateBackoff

			m, err := NewManager(opts)
			require.NoError(t, err)
			m.issueRenewalTimeout = 100 * time.Millisecond

			store := opts.MetadataReader.(storage.Interface)
			meta := metadata.Metadata{VolumeID: "vol-id", TargetPath: "/fake/path"}
			_, err = store.RegisterMetadata(meta)
			require.NoError(t, err)
			defer func() {
				_ = store.RemoveVolume(meta.VolumeID)
			}()

			ctx := t.Context()
			// Mark the eventual CertificateRequest as Issued so the call to
			// m.issue() returns instead of polling forever for completion.
			go testutil.IssueOneRequest(ctx, t, opts.Client, defaultTestNamespace, selfSignedExampleCertificate, []byte("ca bytes"))

			log := testr.New(t)
			start := time.Now()
			m.attemptIssuanceIfDue(ctx, log, meta.VolumeID)
			elapsed := time.Since(start)

			assert.Less(t, elapsed, tc.wantUnder,
				"attemptIssuanceIfDue took %s; expected <%s (likely wrong backoff applied to the wrong error class)", elapsed, tc.wantUnder)

			reqs, listErr := opts.Client.CertmanagerV1().CertificateRequests("").List(ctx, metav1.ListOptions{})
			require.NoError(t, listErr)
			assert.Len(t, reqs.Items, 1, "expected exactly one CertificateRequest after successful issuance")
		})
	}
}

// TestManager_issue_wrapsErrNotReadyToRequest verifies issue() wraps the
// readyToRequest false return with the exported sentinel, so the renewal loop
// (and consumers) can detect gate-pending via errors.Is.
func TestManager_issue_wrapsErrNotReadyToRequest(t *testing.T) {
	opts := newDefaultTestOptions(t)
	opts.ReadyToRequest = func(_ metadata.Metadata) (bool, string) {
		return false, "gate not yet met"
	}

	m, err := NewManager(opts)
	require.NoError(t, err)

	store := opts.MetadataReader.(storage.Interface)
	meta := metadata.Metadata{VolumeID: "vol-id", TargetPath: "/fake/path"}
	_, err = store.RegisterMetadata(meta)
	require.NoError(t, err)

	err = m.issue(t.Context(), meta.VolumeID)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotReadyToRequest), "got %v", err)
	assert.Contains(t, err.Error(), "gate not yet met")
}

// TestManager_NewManager_defaultsGateBackoffConfig locks in the chosen
// defaults for GateBackoffConfig so changes to the defaults are explicit.
func TestManager_NewManager_defaultsGateBackoffConfig(t *testing.T) {
	opts := newDefaultTestOptions(t)
	opts.GateBackoffConfig = nil

	m, err := NewManager(opts)
	require.NoError(t, err)

	assert.Equal(t, time.Second, m.gateBackoffConfig.Duration)
	assert.Equal(t, 2.0, m.gateBackoffConfig.Factor)
	assert.Equal(t, 0.5, m.gateBackoffConfig.Jitter)
	assert.Equal(t, 10*time.Second, m.gateBackoffConfig.Cap)
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
			name: "maxRequestsPerVolume=1: one stale CSR should be left",
			objects: []*cmapi.CertificateRequest{
				cr("cr-1", defaultTestNamespace, "nodeID-1", "volumeID-1"),
				cr("cr-2", defaultTestNamespace, "nodeID-1", "volumeID-1"),
			},
			toBeDeleted: []string{"cr-1"}, // older CR will be deleted
			fields: fields{
				nodeID:               "nodeID-1",
				maxRequestsPerVolume: 1,
			},
			wantErr: false,
		},
		{
			name: "maxRequestsPerVolume=2: 2 stale CSRs should be left",
			objects: []*cmapi.CertificateRequest{
				cr("cr-1", defaultTestNamespace, "nodeID-1", "volumeID-1"),
				cr("cr-2", defaultTestNamespace, "nodeID-1", "volumeID-1"),
			},
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

			for i, req := range test.objects {
				req.CreationTimestamp = metav1.NewTime(time.Now().Add(time.Duration(i) * time.Second))
				if _, err := m.client.CertmanagerV1().CertificateRequests(req.Namespace).Create(ctx, req, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
			}

			// make sure client cache is in sync
			if err := wait.PollUntilContextCancel(ctx, 5*time.Millisecond, false, func(context.Context) (done bool, err error) {
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

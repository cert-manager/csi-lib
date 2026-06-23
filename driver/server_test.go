/*
Copyright 2026 The cert-manager Authors.

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

package driver

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc"
	"k8s.io/klog/v2/ktesting"

	"github.com/cert-manager/csi-lib/metadata"
)

// testToken is a realistic kubelet-injected serviceAccount.tokens blob.
// "secret" is a distinctive substring used throughout to detect leaks.
const testToken = `{"":{"token":"eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.secret","expirationTimestamp":"2099-01-01T00:00:00Z"}}`

func requireNoTokenInOutput(t *testing.T, output string) {
	t.Helper()
	for _, needle := range []string{"secret", "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9"} {
		if strings.Contains(output, needle) {
			t.Errorf("SA token leaked into log output (found %q):\n%s", needle, output)
		}
	}
}

// TestRedactSATokens_NodePublishVolumeRequest verifies that redactSATokens
// replaces the SA token in VolumeContext with "[REDACTED]" without mutating
// the original request or dropping unrelated context keys.
func TestRedactSATokens_NodePublishVolumeRequest(t *testing.T) {
	req := &csi.NodePublishVolumeRequest{
		VolumeId: "vol-123",
		VolumeContext: map[string]string{
			metadata.SATokenVolumeContextKey:         testToken,
			"csi.storage.k8s.io/pod.name":            "my-pod",
			"csi.storage.k8s.io/serviceAccount.name": "my-sa",
		},
	}

	result := redactSATokens(req)

	sanitized, ok := result.(*csi.NodePublishVolumeRequest)
	if !ok {
		t.Fatalf("redactSATokens returned %T, want *csi.NodePublishVolumeRequest", result)
	}
	if sanitized.VolumeContext[metadata.SATokenVolumeContextKey] != "[REDACTED]" {
		t.Errorf("got %q, want [REDACTED]", sanitized.VolumeContext[metadata.SATokenVolumeContextKey])
	}
	if sanitized.VolumeContext["csi.storage.k8s.io/pod.name"] != "my-pod" {
		t.Error("non-sensitive volume context keys were dropped")
	}
	if sanitized.VolumeId != "vol-123" {
		t.Error("VolumeId was altered")
	}
	// Original must not be mutated.
	if req.VolumeContext[metadata.SATokenVolumeContextKey] != testToken {
		t.Error("redactSATokens mutated the original request")
	}
}

// TestRedactSATokens_noToken_returnsOriginal verifies that redactSATokens
// returns the original pointer unchanged when no SA token key is present,
// avoiding unnecessary allocations on the common path.
func TestRedactSATokens_noToken_returnsOriginal(t *testing.T) {
	req := &csi.NodePublishVolumeRequest{
		VolumeId:      "vol-456",
		VolumeContext: map[string]string{"csi.storage.k8s.io/pod.name": "other-pod"},
	}
	if redactSATokens(req) != req {
		t.Error("expected original pointer when no SA token key present")
	}
}

// TestRedactSATokens_nonNodePublishRequest_returnsOriginal verifies that
// redactSATokens is a no-op for request types other than
// NodePublishVolumeRequest, which carry no SA token.
func TestRedactSATokens_nonNodePublishRequest_returnsOriginal(t *testing.T) {
	req := &csi.NodeUnpublishVolumeRequest{VolumeId: "vol-789"}
	if redactSATokens(req) != req {
		t.Error("expected original pointer for non-NodePublishVolumeRequest type")
	}
}

// TestLoggingInterceptor_errorPath_noTokenLeaked covers Sink #3 (error level,
// default verbosity). This fires on any NodePublishVolume handler failure,
// which includes routine conditions such as readOnly not set or issuer timeout.
func TestLoggingInterceptor_errorPath_noTokenLeaked(t *testing.T) {
	logger := ktesting.NewLogger(t, ktesting.NewConfig(ktesting.BufferLogs(true)))
	underlier, _ := logger.GetSink().(ktesting.Underlier)
	interceptor := loggingInterceptor(logger)

	req := &csi.NodePublishVolumeRequest{
		VolumeId: "vol-123",
		VolumeContext: map[string]string{
			metadata.SATokenVolumeContextKey: testToken,
			"csi.storage.k8s.io/pod.name":    "my-pod",
		},
	}

	handler := func(_ context.Context, _ any) (any, error) {
		return nil, fmt.Errorf("simulated handler error")
	}
	info := &grpc.UnaryServerInfo{FullMethod: "/csi.v1.Node/NodePublishVolume"}

	_, _ = interceptor(context.Background(), req, info, handler)

	output := underlier.GetBuffer().String()
	if !strings.Contains(output, "failed processing request") {
		t.Fatalf("expected error log line to be present; got:\n%s", output)
	}
	requireNoTokenInOutput(t, output)
}

// TestLoggingInterceptor_successPath_noTokenLeaked covers Sink #1 (V(3) entry)
// and the V(5) completion line; neither should carry the raw token.
func TestLoggingInterceptor_successPath_noTokenLeaked(t *testing.T) {
	logger := ktesting.NewLogger(t, ktesting.NewConfig(ktesting.BufferLogs(true)))
	underlier, _ := logger.GetSink().(ktesting.Underlier)
	interceptor := loggingInterceptor(logger)

	req := &csi.NodePublishVolumeRequest{
		VolumeId: "vol-456",
		VolumeContext: map[string]string{
			metadata.SATokenVolumeContextKey: testToken,
		},
	}

	handler := func(_ context.Context, _ any) (any, error) {
		return &csi.NodePublishVolumeResponse{}, nil
	}
	info := &grpc.UnaryServerInfo{FullMethod: "/csi.v1.Node/NodePublishVolume"}

	_, _ = interceptor(context.Background(), req, info, handler)

	requireNoTokenInOutput(t, underlier.GetBuffer().String())
}

// TestLoggingInterceptor_metadataLog_noTokenLeaked covers Sink #2 (V(2) in
// manager.go). A caller that logs a Metadata value via a logr.Logger must
// not see the raw token in the output.
func TestLoggingInterceptor_metadataLog_noTokenLeaked(t *testing.T) {
	logger := ktesting.NewLogger(t, ktesting.NewConfig(ktesting.BufferLogs(true)))
	underlier, _ := logger.GetSink().(ktesting.Underlier)

	meta := metadata.Metadata{
		VolumeID:   "vol-789",
		TargetPath: "/var/lib/kubelet/pods/abc/volumes/tls",
		VolumeContext: map[string]string{
			metadata.SATokenVolumeContextKey: testToken,
			"csi.storage.k8s.io/pod.name":    "my-pod",
		},
	}

	// Reproduce the exact call in manager/manager.go:398.
	logger.V(2).Info("Read metadata", "metadata", meta)

	output := underlier.GetBuffer().String()
	if !strings.Contains(output, "Read metadata") {
		t.Fatalf("log line not captured; got:\n%s", output)
	}
	requireNoTokenInOutput(t, output)
}

// TestLoggingInterceptor_originalRequestUnmutated verifies that the handler
// still receives the unmodified request (including the real token) so that
// the driver can use it for token-request authentication.
func TestLoggingInterceptor_originalRequestUnmutated(t *testing.T) {
	logger := ktesting.NewLogger(t, ktesting.DefaultConfig)
	interceptor := loggingInterceptor(logger)

	req := &csi.NodePublishVolumeRequest{
		VolumeId: "vol-123",
		VolumeContext: map[string]string{
			metadata.SATokenVolumeContextKey: testToken,
		},
	}

	var receivedToken string
	handler := func(_ context.Context, raw any) (any, error) {
		r := raw.(*csi.NodePublishVolumeRequest)
		receivedToken = r.VolumeContext[metadata.SATokenVolumeContextKey]
		return &csi.NodePublishVolumeResponse{}, nil
	}
	info := &grpc.UnaryServerInfo{FullMethod: "/csi.v1.Node/NodePublishVolume"}

	_, _ = interceptor(context.Background(), req, info, handler)

	if receivedToken != testToken {
		t.Errorf("handler received mutated token %q, want original", receivedToken)
	}
}

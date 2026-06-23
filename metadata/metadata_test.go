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

package metadata

import (
	"fmt"
	"strings"
	"testing"
)

const testToken = `{"":{"token":"eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.secret","expirationTimestamp":"2099-01-01T00:00:00Z"}}`

// TestMetadata_MarshalLog_redactsSAToken verifies that MarshalLog replaces the
// SA token with "[REDACTED]" without dropping other context keys or mutating
// the original Metadata value.
func TestMetadata_MarshalLog_redactsSAToken(t *testing.T) {
	m := Metadata{
		VolumeID:   "vol-123",
		TargetPath: "/var/lib/kubelet/pods/abc/volumes",
		VolumeContext: map[string]string{
			SATokenVolumeContextKey:                  testToken,
			"csi.storage.k8s.io/pod.name":            "my-pod",
			"csi.storage.k8s.io/serviceAccount.name": "my-sa",
		},
	}

	logged := m.MarshalLog()
	loggedMeta, ok := logged.(Metadata)
	if !ok {
		t.Fatalf("MarshalLog returned %T, want Metadata", logged)
	}
	if loggedMeta.VolumeContext[SATokenVolumeContextKey] != "[REDACTED]" {
		t.Errorf("token not redacted: got %q", loggedMeta.VolumeContext[SATokenVolumeContextKey])
	}
	if loggedMeta.VolumeContext["csi.storage.k8s.io/pod.name"] != "my-pod" {
		t.Error("non-sensitive keys were dropped")
	}
	// Original must not be mutated.
	if m.VolumeContext[SATokenVolumeContextKey] != testToken {
		t.Error("MarshalLog mutated the original Metadata")
	}
}

// TestMetadata_MarshalLog_noToken_passthrough verifies that MarshalLog returns
// the Metadata unchanged when no SA token key is present, ensuring there is no
// unintended key loss on the common (token-free) path.
func TestMetadata_MarshalLog_noToken_passthrough(t *testing.T) {
	m := Metadata{
		VolumeID:      "vol-456",
		VolumeContext: map[string]string{"csi.storage.k8s.io/pod.name": "other-pod"},
	}
	logged := m.MarshalLog()
	loggedMeta, ok := logged.(Metadata)
	if !ok {
		t.Fatalf("MarshalLog returned %T, want Metadata", logged)
	}
	if loggedMeta.VolumeContext["csi.storage.k8s.io/pod.name"] != "other-pod" {
		t.Error("keys dropped from Metadata that has no SA token")
	}
}

// TestMetadata_MarshalLog_tokenNeverInFormattedOutput verifies the
// security property directly: when a logr backend formats the MarshalLog
// return value with %v (the standard fallback for struct types), the raw
// token must not appear in the output string.
func TestMetadata_MarshalLog_tokenNeverInFormattedOutput(t *testing.T) {
	m := Metadata{
		VolumeID: "vol-123",
		VolumeContext: map[string]string{
			SATokenVolumeContextKey: testToken,
		},
	}

	formatted := fmt.Sprintf("%v", m.MarshalLog())

	for _, needle := range []string{"secret", "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9"} {
		if strings.Contains(formatted, needle) {
			t.Errorf("MarshalLog output contains token (found %q):\n%s", needle, formatted)
		}
	}
	if !strings.Contains(formatted, "[REDACTED]") {
		t.Errorf("expected [REDACTED] marker in output:\n%s", formatted)
	}
}

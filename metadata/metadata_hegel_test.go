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
	"maps"
	"testing"

	"hegel.dev/go/hegel"
)

// TestMetadata_MarshalLog_property: for any VolumeContext — arbitrary keys
// and values, with or without the SA token key — MarshalLog returns a
// Metadata whose token entry (if present) is exactly "[REDACTED]", preserves
// every other entry unchanged, and never mutates the original. The
// example-based tests in metadata_test.go pin the formatted-output security
// property; this exercises the redaction rule over arbitrary contexts.
func TestMetadata_MarshalLog_property(t *testing.T) {
	hegel.Test(t, func(ht *hegel.T) {
		vc := map[string]string{}
		for _, k := range hegel.Draw(ht, hegel.Lists(hegel.Text().MaxSize(30)).MaxSize(5)) {
			vc[k] = hegel.Draw(ht, hegel.Text().MaxSize(30))
		}
		hasToken := hegel.Draw(ht, hegel.Booleans())
		if hasToken {
			vc[SATokenVolumeContextKey] = hegel.Draw(ht, hegel.Text().MaxSize(30))
		} else {
			delete(vc, SATokenVolumeContextKey)
		}
		original := maps.Clone(vc)

		m := Metadata{VolumeID: "vol-id", VolumeContext: vc}
		logged, ok := m.MarshalLog().(Metadata)
		if !ok {
			ht.Fatalf("MarshalLog returned %T, want Metadata", m.MarshalLog())
		}

		if !maps.Equal(m.VolumeContext, original) {
			ht.Fatalf("MarshalLog mutated the original VolumeContext: %v != %v", m.VolumeContext, original)
		}
		want := maps.Clone(original)
		if hasToken {
			want[SATokenVolumeContextKey] = "[REDACTED]"
		}
		if !maps.Equal(logged.VolumeContext, want) {
			ht.Fatalf("logged VolumeContext %v, want %v", logged.VolumeContext, want)
		}
	}, hegel.WithTestCases(1000))
}

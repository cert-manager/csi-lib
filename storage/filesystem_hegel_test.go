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

package storage

import (
	"strconv"
	"testing"

	"hegel.dev/go/hegel"

	"github.com/cert-manager/csi-lib/metadata"
)

// drawGroupString draws a candidate fsGroup string: usually a decimal integer
// spanning both boundary checks (including 0, 4294967295 and values beyond
// int64), sometimes arbitrary Unicode text, sometimes empty.
func drawGroupString(ht *hegel.T) string {
	switch hegel.Draw(ht, hegel.Integers(0, 3)) {
	case 0:
		return ""
	case 1:
		return strconv.FormatInt(int64(hegel.Draw(ht, hegel.Integers(-5000000000, 5000000000))), 10)
	case 2:
		// Beyond int64: exercises the strconv.ParseInt overflow error branch.
		return "18446744073709551616"
	default:
		return hegel.Draw(ht, hegel.Text().MaxSize(10))
	}
}

// TestFsGroupForMetadataProperty: fsGroupForMetadata returns the gid parsed
// from the volume attribute named by FSGroupVolumeAttributeKey if that key is
// configured and its value is non-empty, otherwise from
// meta.VolumeMountGroup; an empty effective value means no ownership change
// (nil, nil); anything else must parse as a decimal integer in
// [1, 4294967295] or the call errors. The oracle recomputes that precedence
// and range rule from the drawn parts. Replaces the Test_fsGroupForMetadata
// table, whose nine rows were hand-picked instances of this rule.
func TestFsGroupForMetadataProperty(t *testing.T) {
	hegel.Test(t, func(ht *hegel.T) {
		attrKey := ""
		if hegel.Draw(ht, hegel.Booleans()) {
			attrKey = "fs-gid"
		}
		volumeContext := map[string]string{}
		if hegel.Draw(ht, hegel.Booleans()) {
			volumeContext["fs-gid"] = drawGroupString(ht)
		}
		mountGroup := drawGroupString(ht)

		f := Filesystem{FSGroupVolumeAttributeKey: attrKey}
		gid, err := f.fsGroupForMetadata(metadata.Metadata{
			VolumeContext:    volumeContext,
			VolumeMountGroup: mountGroup,
		})

		effective := ""
		if attrKey != "" {
			effective = volumeContext[attrKey]
		}
		if effective == "" {
			effective = mountGroup
		}

		if effective == "" {
			if err != nil || gid != nil {
				ht.Fatalf("empty effective group: want (nil, nil), got (%v, %v)", gid, err)
			}
			return
		}
		want, parseErr := strconv.ParseInt(effective, 10, 64)
		wantErr := parseErr != nil || want <= 0 || want > 4294967295
		if wantErr {
			if err == nil {
				ht.Fatalf("effective group %q: want error, got gid %v", effective, gid)
			}
			return
		}
		if err != nil {
			ht.Fatalf("effective group %q: unexpected error: %v", effective, err)
		}
		if gid == nil || *gid != want {
			ht.Fatalf("effective group %q: want gid %d, got %v", effective, want, gid)
		}
	}, hegel.WithTestCases(1000))
}

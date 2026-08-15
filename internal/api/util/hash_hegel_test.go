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

package util

import (
	"testing"

	"k8s.io/apimachinery/pkg/util/validation"

	"hegel.dev/go/hegel"
)

// TestHashIdentifierProperty: HashIdentifier exists to turn arbitrary node
// and volume IDs into CertificateRequest label values, so for any input —
// including empty strings and arbitrary Unicode — the output must be a valid
// Kubernetes label value (checked with the apimachinery validator the API
// server itself uses) and must be deterministic. HashIdentifier had no tests.
func TestHashIdentifierProperty(t *testing.T) {
	hegel.Test(t, func(ht *hegel.T) {
		id := hegel.Draw(ht, hegel.Text().MaxSize(100))
		hashed := HashIdentifier(id)
		if errs := validation.IsValidLabelValue(hashed); len(errs) > 0 {
			ht.Fatalf("HashIdentifier(%q) = %q is not a valid label value: %v", id, hashed, errs)
		}
		if again := HashIdentifier(id); again != hashed {
			ht.Fatalf("HashIdentifier(%q) is not deterministic: %q != %q", id, hashed, again)
		}
	}, hegel.WithTestCases(1000))
}

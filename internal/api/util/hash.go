package util

import (
	"fmt"
	"hash/fnv"
	"k8s.io/apimachinery/pkg/util/rand"
)

// HashIdentifier is the function used to hash a Node ID or Volume ID for use
// as a label value on created CertificateRequest resources.
func HashIdentifier(s string) string {
	hf := fnv.New32()
	hf.Write([]byte(s))
	return rand.SafeEncodeString(fmt.Sprint(hf.Sum32()))
}

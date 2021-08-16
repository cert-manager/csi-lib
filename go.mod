module github.com/cert-manager/csi-lib

go 1.16

require (
	github.com/container-storage-interface/spec v1.4.0
	github.com/go-logr/logr v0.4.0
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/jetstack/cert-manager v1.3.1
	github.com/kubernetes-csi/csi-lib-utils v0.9.1
	github.com/stretchr/testify v1.6.1
	golang.org/x/net v0.0.0-20210224082022-3d97a244fca7
	google.golang.org/grpc v1.37.0
	k8s.io/apimachinery v0.21.0
	k8s.io/client-go v0.21.0
	k8s.io/klog/v2 v2.8.0
	k8s.io/mount-utils v0.21.0
	k8s.io/utils v0.0.0-20201110183641-67b214c5f920
)

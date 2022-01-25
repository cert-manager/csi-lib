module github.com/cert-manager/csi-lib

go 1.16

require (
	github.com/container-storage-interface/spec v1.4.0
	github.com/go-logr/logr v1.2.0
	github.com/jetstack/cert-manager v1.7.0-beta.0
	github.com/kubernetes-csi/csi-lib-utils v0.9.1
	github.com/stretchr/testify v1.7.0
	golang.org/x/net v0.0.0-20211209124913-491a49abca63
	google.golang.org/grpc v1.43.0
	k8s.io/apimachinery v0.23.1
	k8s.io/client-go v0.23.1
	k8s.io/klog/v2 v2.30.0
	k8s.io/mount-utils v0.21.0
	k8s.io/utils v0.0.0-20210930125809-cb0fa318a74b
)

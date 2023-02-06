<p align="center">
  <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" height="256" width="256" alt="cert-manager project logo" />
</p>

<p align="center">
  <a href="https://godoc.org/github.com/cert-manager/csi-lib"><img src="https://godoc.org/github.com/cert-manager/csi-lib?status.svg" alt="cert-manager/csi-lib godoc"></a>
</p>

# cert-manager-csi-lib

A library for building [CSI drivers](https://kubernetes-csi.github.io/docs/)
which interact with [cert-manager's](https://github.com/cert-manager/cert-manager)
CertificateRequest API.

## Introduction

To provide identity documents and TLS certificates to Kubernetes Pods, a CSI
driver can be used which automatically provisions, rotates and exposes
certificates at a user-configured path on a filesystem.

This avoids user applications needing to understand how these identities are
procured, and allows them to be fetched from any supported cert-manager issuer.

This project is first and foremost presented as a library to better support
those wanting to build their own more opinionated identity provisioning drivers
whilst still benefiting from the support and adoption of the cert-manager
project.

For example, despite the vast configurability of cert-manager's
CertificateRequest resource, you may want to restrict/dictate the options used
on the certificates (and their corresponding private key).
This means your security teams can be confident that these complex identity
documents are being handled, configured and procured in a manner which meets
the organisational goals you have in place.

## Goals

This library makes it easy to create your own, potentially opinionated, CSI
drivers.

It takes care of:

- Implementing the CSI interface
- Communicating with the Kubernetes/cert-manager API via CertificateRequests
- Automatically rotating/renewing certificates near expiry
- Managing private key & certificate data on disk
- Exposing private key & certificate data to pods
- Atomically updating written data (to avoid mismatching identity documents)

## Usage

An example implementation of the CSI driver can be found in the [`example/`](./example)
subdirectory.

This presents a highly configurable CSI driver which allows users to configure
the options used when generating private keys and certificate requests using
CSI volume attributes (specified in-line on a pod).

If you intend to implement your own CSI driver, the [`manager/interfaces.go`](./manager/interfaces.go)
file defines the functions and interfaces you will need to implement.

## Contributing

This is a part of the cert-manager project and therefore follows the same
contribution workflow.

Pull requests are welcome, however we strongly recommend creating an issue
**before** beginning work on your change else there will likely be additional
revisions/changes needed before it can be accepted.

# CertificateRequest management

A core part of the CSI driver's functionality is to create CertificateRequest resources in a Kubernetes API
server to request and fetch signed certificates for a given CSI volume.

To avoid amassing a large amount of old/no longer relevant resources, it is important that these are not only
created by also cleaned up/deleted on some schedule.
It is also essential that the rate at which CertificateRequest resources is limited, to avoid creating huge
amounts of resources in the target apiserver (which can hinder performance and potentially cause outages).

This document discusses and proposes a way for this deletion/garbage collection to happen.

## Goals

* Automatically cleaning up CertificateRequest resources
* Retaining a limited history of CertificateRequest resources
* Controlling the rate of CertificateRequest creation

## Non-goals

* A general purpose solution for use outside the cert-manager-csi project (i.e. a general purpose controller)

## Proposal

This proposal is split into two parts: cleanup handling and rate-limiting of request creation. Both can be
considered independently of the other, however they are discussed together here to provide a clear overview
of the CertificateRequest management process.

### Cleanup

The CSI library will be extended to only retain a configurable number of CertificateRequests for each CSI
volume under management. This will be configurable by consumers of the library when instantiating a `manager`.

When the manager's `issue` function is called (the internal function that initiates a new CertificateRequest),
a cleanup routine will be run that will delete the oldest CertificateRequests for the given volume until
there is fewer than the configured revision history limit. To identify which requests should be deleted, they
will be sorted by `metadata.creationTimestamp`.

To achieve this, the CSI library will need to establish a list/watch on CertificateRequest resources.
To avoid excess memory consumption in having all instances of the CSI driver maintaining an index of every
CertificateRequest cluster wide, a label containing the node name will be added to each CertificateRequest
resource that is created, and the list/watch will be established using a label selector.

The full list of new labels to be added to CertificateRequest resources:

* `csi.cert-manager.io/node-name` - the name of the node that the related pod is running on (taken from the
  driver's `DriverID` field). Used to establish efficient watches on the apiserver.
* `csi.cert-manager.io/pod-name` - the name of the pod that the CertificateRequest is created for. Used to
  allow for efficient cross-referencing of CertificateRequest<>Pod (this is not strictly necessary as owner
  references are also added to CertificateRequests, but this does make it easier for administrators to debug
  any issues with issuance too).
* `csi.cert-manager.io/volume-name` - the name of the volume within the pod that the CertificateRequest is
  created for. This is required because a pod may contain multiple volume mounts, in which case we must maintain
  a history of CertificateRequests for each volume within the Pod.

When CertificateRequest resources are created, random names will continue to be used (via the `metadata.generateName`
field). This ensures we avoid any conflicts upon re-issuance, and means we do not need explicit naming conflict
handling within the driver, simplifying the design.

#### Open questions

* Is every possible Kubernetes node name a valid label value? If not, hashing of the node name will be required
  to avoid situations where a CertificateRequest cannot be created due to node names not being valid label values.

### Rate-limiting/back-off

After a CertificateRequest *fails* to complete, it is important that the CSI driver does not continuously create
new CertificateRequest resources without some form of back-off.

As part of the cleanup changes, the manager will also be extended to support exponential back-off on a per-volume
basis.

The state for this exponential back-off will be kept in memory, which simplifies the design & implementation.
By maintaining this in memory, it MAY mean that upon the CSI driver restarting we may encounter bursts of retries
(if for example there are many failing volumes on a single node). This will not be accounted for as part of this
proposal, however it may be necessary for us to add a global rate-limit & request jitter to help alleviate these
issues.

## Alternatives considered

* Maintaining a time-based history of CertificateRequest resources (i.e. deleting CertificateRequests in a terminal
  state that are older than 1h). This was decided against as it does not clearly bound the number of resources that
  could be created whereas a strict revision limit will. It may be worthwhile implementing a time-bound _as well as_
  a revision limit in future, to avoid N CertificateRequest resources existing in cases where requests are _not_
  failing (e.g. during renewal, it may not be valuable to retain older instances of the requests).

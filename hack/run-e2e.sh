#!/usr/bin/env bash

# Copyright 2022 The cert-manager Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

delete_cluster() {
  kind delete cluster --name cert-manager-csi-e2e
}

ROOT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )/.."
cd "$ROOT_DIR"

# Add user nix config so that flakes are enabled for the script.
export NIX_USER_CONF_FILES=${ROOT_DIR}/hack/nix/nix.conf

TMP_DIR=$(mktemp -d)
trap "rm -rf $TMP_DIR" EXIT

# If this environment variable is not set, then that means that we are no in a
# nix shell, and the command was not invoked with `nix develop -c
# ./hack/run-e2e.sh` or similar.
if ! [ -v IN_NIX_SHELL ]; then
  exec nix develop -c "${ROOT_DIR}/hack/run-e2e.sh"
fi

ginkgo version
kind version
echo "helm $(helm version)"
echo "kubectl $(kubectl version --client)"
echo "docker"
docker version

echo "> Creating cluster..."
docker load < $(nix build --print-out-paths '.#kind-node-image')
trap delete_cluster EXIT
kind create cluster --name cert-manager-csi-e2e

kind get kubeconfig --name cert-manager-csi-e2e > "$TMP_DIR/kubeconfig"
export KUBECONFIG="$TMP_DIR/kubeconfig"

echo "> Loading cert-manager images..."
kind load image-archive --name cert-manager-csi-e2e $(nix build --print-out-paths '.#cert-manager-controller-image') &
kind load image-archive --name cert-manager-csi-e2e $(nix build --print-out-paths '.#cert-manager-webhook-image') &
kind load image-archive --name cert-manager-csi-e2e $(nix build --print-out-paths '.#cert-manager-cainjector-image') &
kind load image-archive --name cert-manager-csi-e2e $(nix build --print-out-paths '.#cert-manager-ctl-image') &

echo "> Loading busybox image..."
kind load image-archive --name cert-manager-csi-e2e $(nix build --print-out-paths '.#busybox-image') &

echo "> Loading csi-lib docker image..."
kind load image-archive --name cert-manager-csi-e2e <(gzip --decompress --stdout $(nix build --print-out-paths '.#container')) &
kind load image-archive --name cert-manager-csi-e2e $(nix build --print-out-paths '.#csi-node-driver-registrar-image') &

wait

echo "> Installing cert-manager..."
helm install cert-manager --set installCRDs=true -n cert-manager --create-namespace --wait \
  $(nix build --print-out-paths '.#cert-manager-helm-chart')

echo "> Installing csi-driver..."
kubectl apply -f ./deploy/cert-manager-csi-driver.yaml
kubectl apply -f ./deploy/example
kubectl get pods -A

echo "> Waiting for all pods to be ready..."
kubectl wait --for=condition=Ready pod --all --all-namespaces --timeout=5m

echo "> Running tests"
csi-lib-e2e

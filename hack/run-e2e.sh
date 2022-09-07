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


CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-v1.9.1}"

ROOT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )/.."
cd "$ROOT_DIR"

check_command() {
  if ! [ -x "$(command -v $1)" ]; then
    echo "Error: $1 is not installed." >&2
    echo "Invoke script using 'nix develop -c ./hack/run.sh'" >&2
    echo "https://nixos.org/download.html" >&2
    exit 1
  fi
}

delete_cluster() {
  kind delete cluster --name cert-manager-csi-e2e
}

for cmd in ginkgo docker kind kubectl helm nix csi-lib-e2e; do
  check_command $cmd
done

ginkgo version
kind version
echo "helm $(helm version)"
echo "kubectl $(kubectl version --client)"
echo "docker"
docker version

echo "> Creating cluster..."
kind create cluster --name cert-manager-csi-e2e
trap delete_cluster EXIT

echo "> Loading csi-lib docker container..."
nix build .#container
kind load image-archive --name cert-manager-csi-e2e <(gzip --decompress --stdout result)

echo "> Installing cert-manager..."
helm repo add --force-update jetstack https://charts.jetstack.io
helm upgrade -i cert-manager jetstack/cert-manager --set installCRDs=true --version $CERT_MANAGER_VERSION -n cert-manager --create-namespace --wait

echo "> Installing csi-driver..."
kubectl apply -f ./deploy/cert-manager-csi-driver.yaml
kubectl apply -f ./deploy/example
kubectl get pods -A

echo "> Waiting for all pods to be ready..."
kubectl wait --for=condition=Ready pod --all --all-namespaces --timeout=5m


echo "> Running tests"
csi-lib-e2e

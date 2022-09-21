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

#set -o errexit
#set -o nounset
#set -o pipefail
#
#ginkgo version
#kind version
#echo "helm $(helm version)"
#echo "kubectl $(kubectl version --client)"
#echo "docker"
#docker version

#echo "> Loading docker images ..."
#for IMAGE in ${DOCKER_IMAGES}; do
#  docker load < "${IMAGE}" &
#done
#
#wait
#
#echo "> Creating cluster ..."
#kind create cluster --name cert-manager-csi-e2e
#
#kind get kubeconfig --name cert-manager-csi-e2e > "$TMP_DIR/kubeconfig"
#export KUBECONFIG="$TMP_DIR/kubeconfig"
#
#echo "> Loading kind images ..."
#for IMAGE in ${KIND_IMAGES}; do
#  kind load docker-image --name cert-manager-csi-e2e "${IMAGE}" &
#done
#
#wait
#
#echo "> Installing cert-manager..."
#helm install cert-manager --set installCRDs=true -n cert-manager --create-namespace --wait \
#  $(nix build --print-out-paths '.#chart-cert-manager')
#
#echo "> Installing csi-driver..."
#kubectl apply -f ./deploy/cert-manager-csi-driver.yaml
#kubectl apply -f ./deploy/example
#kubectl get pods -A
#
#echo "> Waiting for all pods to be ready..."
#kubectl wait --for=condition=Ready pod --all --all-namespaces --timeout=5m
#
#echo "> Running tests"
#csi-lib-e2e

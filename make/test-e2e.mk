# Copyright 2023 The cert-manager Authors.
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

.PHONY: e2e-setup-cert-manager
e2e-setup-cert-manager: | kind-cluster $(NEEDS_HELM) $(NEEDS_KUBECTL)
	$(HELM) upgrade \
		--install \
		--create-namespace \
		--wait \
		--version $(quay.io/jetstack/cert-manager-controller.TAG) \
		--namespace cert-manager \
		--repo https://charts.jetstack.io \
		--set installCRDs=true \
		--set image.repository=$(quay.io/jetstack/cert-manager-controller.REPO) \
		--set image.tag=$(quay.io/jetstack/cert-manager-controller.TAG) \
		--set image.pullPolicy=Never \
		--set cainjector.image.repository=$(quay.io/jetstack/cert-manager-cainjector.REPO) \
		--set cainjector.image.tag=$(quay.io/jetstack/cert-manager-cainjector.TAG) \
		--set cainjector.image.pullPolicy=Never \
		--set webhook.image.repository=$(quay.io/jetstack/cert-manager-webhook.REPO) \
		--set webhook.image.tag=$(quay.io/jetstack/cert-manager-webhook.TAG) \
		--set webhook.image.pullPolicy=Never \
		--set startupapicheck.image.repository=$(quay.io/jetstack/cert-manager-startupapicheck.REPO) \
		--set startupapicheck.image.tag=$(quay.io/jetstack/cert-manager-startupapicheck.TAG) \
		--set startupapicheck.image.pullPolicy=Never \
		cert-manager cert-manager >/dev/null

	$(KUBECTL) -n cert-manager apply -f ./make/config/cert-manager/approve.yaml

$(bin_dir)/scratch/yaml/kustomization.yaml: FORCE | $(NEEDS_KUSTOMIZE)
	rm -rf $(bin_dir)/scratch/yaml
	mkdir -p $(bin_dir)/scratch/yaml

	cd $(bin_dir)/scratch/yaml; \
	$(KUSTOMIZE) create \
		--resources ../../../examples/simple/deploy/

	cd $(bin_dir)/scratch/yaml; \
	$(KUSTOMIZE) edit set image "simple-csi:latest=$(oci_manager_image_name_development):$(oci_manager_image_tag)"

.PHONY: e2e-setup-simple-issuer
e2e-setup-simple-issuer: $(bin_dir)/scratch/yaml/kustomization.yaml | oci-load-manager e2e-setup-cert-manager kind-cluster $(NEEDS_KUBECTL)
	$(KUBECTL) apply -k $(bin_dir)/scratch/yaml/

test-e2e-deps: e2e-setup-cert-manager
test-e2e-deps: e2e-setup-simple-issuer

.PHONY: test-e2e
## Smoke end-to-end tests
## @category Testing
test-e2e: test-e2e-deps | kind-cluster $(NEEDS_GOTESTSUM) $(ARTIFACTS)
	$(eval abs_artifacts := $(abspath $(ARTIFACTS)))

	cd ./examples/simple && \
	GOWORK=off \
	KUBECONFIG=$(CURDIR)/$(kind_kubeconfig) \
	./test/test.sh

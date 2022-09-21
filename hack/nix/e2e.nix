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

{ pkgs
, cmpkgs
, csi-lib-image
, csi-lib-e2e
}:

let
  # Block of aliases for the packages needed for e2e test.
  e2e-deps = {
    deploy = ../../deploy;
    images = {
      cm-controller = cmpkgs."image/quay_io/jetstack/cert-manager-controller:preferred";
      cm-webhook = cmpkgs."image/quay_io/jetstack/cert-manager-webhook:preferred";
      cm-cainjector = cmpkgs."image/quay_io/jetstack/cert-manager-cainjector:preferred";
      cm-ctl = cmpkgs."image/quay_io/jetstack/cert-manager-ctl:preferred";
      busybox = cmpkgs."image/busybox:preferred";
      node-registrar = cmpkgs."image/k8s_gcr_io/sig-storage/csi-node-driver-registrar:preferred";
      kindest-node = cmpkgs."image/kindest/node:preferred";
    };
    charts = {
      cert-manager = cmpkgs."chart/https://charts_jetstack_io/charts/cert-manager:preferred";
    };
  };

  test-vm = pkgs.nixosTest {
    name = "csi-lib e2e test";
    nodes = {
      machine = { ... }: {
        boot.kernelPackages = pkgs.linuxPackages;
        networking.hostId = "deadbeef";
        virtualisation = {
          docker.enable = true;
          diskSize = 5 * 1024;
          memorySize = 4 * 1024;
          cores = 8;
        };
        environment.systemPackages = [
          pkgs.ginkgo pkgs.gzip pkgs.kind pkgs.docker
          pkgs.kubernetes-helm pkgs.kubectl csi-lib-e2e
        ];
      };
    };

    testScript = ''
      start_all()

      machine.succeed(
        "ginkgo version",
        "kind version",
        "echo helm && helm version",
        "echo kubectl && kubectl version --client",
        "echo docker && docker version",
      )

      # Load kind image and create cluster.
      machine.succeed(
        "docker load --input='${e2e-deps.images.kindest-node}'",
        "kind create cluster --image d3da246e125a",
      )

      # Load kind images.
      machine.succeed(
        "kind load image-archive ${e2e-deps.images.cm-controller}",
        "kind load image-archive ${e2e-deps.images.cm-webhook}",
        "kind load image-archive ${e2e-deps.images.cm-cainjector}",
        "kind load image-archive ${e2e-deps.images.cm-ctl}",
        "kind load image-archive ${e2e-deps.images.busybox}",
        "kind load image-archive ${e2e-deps.images.node-registrar}",
        "kind load image-archive <(gzip --decompress --stdout ${csi-lib-image})",
      )

      # Install cert-manager and example csi-driver using csi-lib.
      machine.succeed(
        "helm install cert-manager --set installCRDs=true -n cert-manager \
          --create-namespace ${e2e-deps.charts.cert-manager} --wait",

        "kubectl apply -f ${e2e-deps.deploy}/cert-manager-csi-driver.yaml",
        "kubectl apply -f ${e2e-deps.deploy}/example",
        "kubectl get pods -A",
        "kubectl wait --for=condition=Ready pod --all --all-namespaces --timeout=5m",
      )

      # Run e2e binary against cluster. Capture logs.
      # Always return true to avoid failing the derivation build, instead
      # opting for writing the test logs and success result.
      try:
        machine.succeed("csi-lib-e2e &> test-results.log")
      except:
        machine.succeed("echo 1 > test-results.code")
      else:
        machine.succeed("echo 0 > test-results.code")
      finally:
        machine.copy_from_vm("test-results.log", "")
        machine.copy_from_vm("test-results.code", "")
        True
    '';
  };

in test-vm

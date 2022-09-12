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

{
  description = ''
    cert-manager/csi-lib

    Go libary for building CSI drivers to deliver cert-manager signed
    certificate key pairs to Kubernetes workloads.
  '';

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; overlays = [ (import ./hack/nix/overlay-kind.nix) ]; };

        # We only source go files to have better cache hits when actively
        # working on non-go files.
        src = pkgs.lib.sourceFilesBySuffices ./. [ ".go" "go.mod" "go.sum" ];
        vendorSha256 = "sha256-jxiwax8g+ZtiR66UFUfMt5QQ7lGAH6wR3iPugmFZ/hc=";
        src-e2e = pkgs.lib.sourceFilesBySuffices ./test/e2e [ ".go" "go.mod" "go.sum" ];
        csi-lib-e2e-vendorSha256 = "sha256-AlovNqQCh+Yvw0Y6zRc24mzLqxMobjjip7Yhi004ROM=";

        e2e-cert-manager-version = "1.9.1";
        e2e-cert-manager-controller-digest = "sha256:cd9bf3d48b6b8402a2a8b11953f9dc0275ba4beec14da47e31823a0515cde7e2";
        e2e-cert-manager-controller-sha256 = "sha256-NQcTUOuqmHDWqD8kMhE8AApZmsNa3ElXlHe5qyCrSJs=";
        e2e-cert-manager-webhook-digest = "sha256:4ab2982a220e1c719473d52d8463508422ab26e92664732bfc4d96b538af6b8a";
        e2e-cert-manager-webhook-sha256 = "sha256-Nr1xSnXhIdobf3vPqnf8iS/8FbXN+yEEz+KpdmVKB3w=";
        e2e-cert-manager-cainjector-digest = "sha256:df7f0b5186ddb84eccb383ed4b10ec8b8e2a52e0e599ec51f98086af5f4b4938";
        e2e-cert-manager-cainjector-sha256 = "sha256-Bf9AJzjwnsF3oi37UAMa9DN9LXZ2AMlt9kjpsRyFBHg=";
        e2e-cert-manager-ctl-digest = "sha256:468c868b2cbae19a5d54d34b6f1c27fe54b0b3988a6d8cab74455f5411d95e96";
        e2e-cert-manager-ctl-sha256 = "sha256-D0ZOewtFI3on6U2ALdbBZZwlwA6uPkyQLXnCbMlZyoQ=";

        e2e-kind-node-version = "1.25.0";
        e2e-kind-node-digest = "sha256:428aaa17ec82ccde0131cb2d1ca6547d13cf5fdabcc0bbecf749baa935387cbf";
        e2e-kind-node-sha256 = "sha256-s8kIavYmei38a+PrWjj54BDW9grLP8tRU09XkQ2zAME=";

        csi-node-driver-registrar-version = "1.2.0";
        csi-node-driver-registrar-digest = "sha256:89cdb2a20bdec89b75e2fbd82a67567ea90b719524990e772f2704b19757188d";
        csi-node-driver-registrar-sha256 = "sha256-yve52Xxoyc00lOJGPACijt+3VQX6ngXtfl6nGqbFsIw=";

        e2e-busybox-digest = "sha256:b8f68c62fe862281bf598060f15cb080ef778dc9db19f136d19a3531ffcb9aa0";
        e2e-busybox-sha256 = "sha256-E0PakwKrCGFybyKC3BW/LW43oHiiCXQuT4dKtHrdNc4=";

        cert-manager-csi = pkgs.buildGo119Module {
          name = "cert-manager-csi";
          inherit src vendorSha256;
          subPackages = [ "./example" ];
          postInstall = "mv $out/bin/example $out/bin/cert-manager-csi";
        };

        # e2e test binary.
        csi-lib-e2e = pkgs.buildGo119Module {
          name = "csi-lib-e2e";
          src = src-e2e;
          vendorSha256 = csi-lib-e2e-vendorSha256;
          # We need to use a custom `buildPhase` so that we can build the e2e
          # binary using `go test` instead of `go build`.
          buildPhase = ''
            go test -v --race -o csi-lib-e2e -c ./.
          '';
        };

        containerImage = pkgs.dockerTools.buildImage {
          name = "cert-manager-csi";
          tag = "example";
          # mount and umount are required for csi-driver functions.
          copyToRoot = pkgs.buildEnv {
            name = "mount-bin";
            pathsToLink = [ "/bin" ];
            paths = [ pkgs.mount pkgs.umount ];
          };
          config = {
            Description = "cert-manager CSI Driver";
            Entrypoint = [ "${cert-manager-csi}/bin/cert-manager-csi" ];
          };
        };

        cert-manager-helm-chart = pkgs.fetchurl {
          url = "https://charts.jetstack.io/charts/cert-manager-v${e2e-cert-manager-version}.tgz";
          sha256 = "sha256-Ricxd7XKaTCvgEfNUr8LeEyEgqwELngS0IZDwomGktU=";
        };

        kind-node-image = pkgs.dockerTools.pullImage{
          imageName = "kindest/node";
          imageDigest = e2e-kind-node-digest;
          sha256 = e2e-kind-node-sha256;
          finalImageTag = "v${e2e-kind-node-version}";
          finalImageName = "kindest/node";
        };

        cert-manager-controller-image = pkgs.dockerTools.pullImage{
          imageName = "quay.io/jetstack/cert-manager-controller";
          imageDigest = e2e-cert-manager-controller-digest;
          sha256 = e2e-cert-manager-controller-sha256;
          finalImageTag = e2e-cert-manager-version;
          finalImageName = "quay.io/jetstack/cert-manager-controller";
        };

        cert-manager-webhook-image = pkgs.dockerTools.pullImage{
          imageName = "quay.io/jetstack/cert-manager-webhook";
          imageDigest = e2e-cert-manager-webhook-digest;
          sha256 = e2e-cert-manager-webhook-sha256;
          finalImageTag = e2e-cert-manager-version;
          finalImageName = "quay.io/jetstack/cert-manager-webhook";
        };

        cert-manager-cainjector-image = pkgs.dockerTools.pullImage{
          imageName = "quay.io/jetstack/cert-manager-cainjector";
          imageDigest = e2e-cert-manager-cainjector-digest;
          sha256 = e2e-cert-manager-cainjector-sha256;
          finalImageTag = e2e-cert-manager-version;
          finalImageName = "quay.io/jetstack/cert-manager-cainjector";
        };

        cert-manager-ctl-image = pkgs.dockerTools.pullImage{
          imageName = "quay.io/jetstack/cert-manager-ctl";
          imageDigest = e2e-cert-manager-ctl-digest;
          sha256 = e2e-cert-manager-ctl-sha256;
          finalImageTag = e2e-cert-manager-version;
          finalImageName = "quay.io/jetstack/cert-manager-ctl";
        };

        csi-node-driver-registrar-image = pkgs.dockerTools.pullImage{
          imageName = "quay.io/k8scsi/csi-node-driver-registrar";
          imageDigest = csi-node-driver-registrar-digest;
          sha256 = csi-node-driver-registrar-sha256;
          finalImageTag = "v${csi-node-driver-registrar-version}";
          finalImageName = "quay.io/k8scsi/csi-node-driver-registrar";
        };

        busybox-image = pkgs.dockerTools.pullImage{
          imageName = "busybox";
          imageDigest = e2e-busybox-digest;
          sha256 = e2e-busybox-sha256;
          finalImageTag = "latest";
          finalImageName = "busybox";
        };

      in {
        packages = {
          default = containerImage;
          container = containerImage;
          inherit cert-manager-helm-chart;
          inherit kind-node-image;
          inherit cert-manager-controller-image;
          inherit cert-manager-webhook-image;
          inherit cert-manager-cainjector-image;
          inherit cert-manager-ctl-image;
          inherit cert-manager-csi;
          inherit busybox-image;
          inherit csi-node-driver-registrar-image;
          inherit csi-lib-e2e;
        };
        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.kubectl
            pkgs.kubernetes-helm
            pkgs.ginkgo
            pkgs.docker
            pkgs.kind
            cert-manager-csi
            csi-lib-e2e
          ];
        };
    });
}

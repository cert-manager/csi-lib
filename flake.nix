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
    let
      # We only source go files to have better cache hits when actively
      # working on non-go files.
      src = nixpkgs.lib.sourceFilesBySuffices ./. [ ".go" "go.mod" "go.sum" ];
      vendorSha256 = "sha256-jxiwax8g+ZtiR66UFUfMt5QQ7lGAH6wR3iPugmFZ/hc=";
      src-e2e = nixpkgs.lib.sourceFilesBySuffices ./test/e2e [ ".go" "go.mod" "go.sum" ];
      csi-lib-e2e-vendorSha256 = "sha256-AlovNqQCh+Yvw0Y6zRc24mzLqxMobjjip7Yhi004ROM=";

      # Container images can be fetch using the following:
      # $ nix-shell -p nix-prefetch-docker
      # $ nix-prefetch-docker --image-name quay.io/jetstack/cert-manager-controller --image-tag v1.9.1 --arch amd64 --os linux
      cert-manager-version = "1.9.1";
      cert-manager-controller = rec {
        imageName = "quay.io/jetstack/cert-manager-controller";
        finalImageName = "quay.io/jetstack/cert-manager-controller";
        finalImageTag = "v${cert-manager-version}";
        os = "linux";
        imageDigest = "sha256:81a5e25e2ecf63b96d6a0be28348d08a3055ea75793373109036977c24e34cf0";
        x86_64-linux = {
          sha256 = "0k7kv02zy456n3fg5d4k1ysl7jnrr5k11249pxdwf5xdxayppjz7";
          arch = "amd64";
        };
        aarch64-linux = {
          sha256 = "0h1zsnhshb55cw21x7cvndy3nilar65cdxa2n83zm6qf1a7d6sz8";
          arch = "arm64";
        };
        x86_64-darwin = x86_64-linux;
        aarch64-darwin = aarch64-linux;
      };

      cert-manager-webhook = rec {
        imageName = "quay.io/jetstack/cert-manager-webhook";
        finalImageName = "quay.io/jetstack/cert-manager-webhook";
        finalImageTag = "v${cert-manager-version}";
        imageDigest = "sha256:4ab2982a220e1c719473d52d8463508422ab26e92664732bfc4d96b538af6b8a";
        os = "linux";
        x86_64-linux = {
          sha256 = "0gg404ypk9drjmmm0bfws5p20433bvgail7181bljlxdprywsck1";
          arch = "amd64";
        };
        aarch64-linux = {
          sha256 = "06qdf6aplkk7klszp62rf3my6drwdinpp8c3drnamr45b828b69v";
          arch = "arm64";
        };
        x86_64-darwin = x86_64-linux;
        aarch64-darwin = aarch64-linux;
      };

      cert-manager-cainjector = rec {
        imageName = "quay.io/jetstack/cert-manager-cainjector";
        finalImageName = "quay.io/jetstack/cert-manager-cainjector";
        finalImageTag = "v${cert-manager-version}";
        imageDigest = "sha256:df7f0b5186ddb84eccb383ed4b10ec8b8e2a52e0e599ec51f98086af5f4b4938";
        os = "linux";
        x86_64-linux = {
          sha256 = "1ybl4sca2f2zslxa0rspriln275m30lpzamnad0p9wfh131gnfxd";
          arch = "amd64";
        };
        aarch64-linux = {
          sha256 = "1yskd7scwk3lgiz1f9akpgp073856yi4z3njpfvg1kw7c91dnr1l";
          arch = "arm64";
        };
        x86_64-darwin = x86_64-linux;
        aarch64-darwin = aarch64-linux;
      };

      cert-manager-ctl = rec {
        imageName = "quay.io/jetstack/cert-manager-ctl";
        finalImageName = "quay.io/jetstack/cert-manager-ctl";
        finalImageTag = "v${cert-manager-version}";
        imageDigest = "sha256:468c868b2cbae19a5d54d34b6f1c27fe54b0b3988a6d8cab74455f5411d95e96";
        os = "linux";
        x86_64-linux = {
          sha256 = "1r7a82x6cp936dnp6jlm6k74gkjwmzx23m0bad6j85gycxy7klgw";
          arch = "amd64";
        };
        aarch64-linux = {
          sha256 = "1sjjx0yjagh7m7lav6ymysms6h4pbpwpmp7xqzrdpph4dcq065bh";
          arch = "arm64";
        };
        x86_64-darwin = x86_64-linux;
        aarch64-darwin = aarch64-linux;
      };

      csi-node-driver-registrar = rec {
        imageName = "k8s.gcr.io/sig-storage/csi-node-driver-registrar";
        finalImageName = "k8s.gcr.io/sig-storage/csi-node-driver-registrar";
        finalImageTag = "v2.5.0";
        imageDigest = "sha256:4fd21f36075b44d1a423dfb262ad79202ce54e95f5cbc4622a6c1c38ab287ad6";
        os = "linux";
        x86_64-linux = {
          sha256 = "1zb161ak2chhblv1yq86j34l2r2i2fsnk4zsvrwzxrsbpw42wg05";
          arch = "amd64";
        };
        aarch64-linux = {
          sha256 = "0hdjhm69fr9dz4msn3bll250mhwkxzm31k5b7wf3yynibrbanw1c";
          arch = "arm64";
        };
        x86_64-darwin = x86_64-linux;
        aarch64-darwin = aarch64-linux;
      };

      kind-node = rec {
        imageName = "kindest/node";
        finalImageName = "kindest/node";
        finalImageTag = "v1.25.0";
        imageDigest = "sha256:428aaa17ec82ccde0131cb2d1ca6547d13cf5fdabcc0bbecf749baa935387cbf";
        os = "linux";
        x86_64-linux = {
          sha256 = "1h80nc6r2msgad8wngyb1bvdc470z4w5msz3dgy2syi6yrm0ijdk";
          arch = "amd64";
        };
        aarch64-linux = {
          sha256 = "1wssixpg4bcjl65s1361n41ccr2l3aad9dg1vhp6fvxdvlzj2r60";
          arch = "arm64";
        };
        x86_64-darwin = x86_64-linux;
        aarch64-darwin = aarch64-linux;
      };

      busybox = rec {
        imageName = "busybox";
        finalImageName = "busybox";
        finalImageTag = "latest";
        imageDigest = "sha256:20142e89dab967c01765b0aea3be4cec3a5957cc330f061e5503ef6168ae6613";
        os = "linux";
        x86_64-linux = {
          sha256 = "01rjvdi19287bqgl19wmkp4srn49xlr8bik8r0fhz7rfmh3lqa1g";
          arch = "amd64";
        };
        aarch64-linux = {
          sha256 = "1yn3fhkii1c2h2d103xg5j1nsh6bszsjp42jnz9mxv5way6ca7yx";
          arch = "arm64";
        };
        x86_64-darwin = x86_64-linux;
        aarch64-darwin = aarch64-linux;
      };

    in
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

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
            go test -v --race -o $GOPATH/bin/csi-lib-e2e -c ./.
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
          url = "https://charts.jetstack.io/charts/cert-manager-v${cert-manager-version}.tgz";
          sha256 = "sha256-Ricxd7XKaTCvgEfNUr8LeEyEgqwELngS0IZDwomGktU=";
        };

        cert-manager-controller-image = pkgs.dockerTools.pullImage {
          inherit (cert-manager-controller) imageName finalImageName finalImageTag imageDigest os;
          inherit (cert-manager-controller.${system}) sha256 arch;
        };

        cert-manager-webhook-image = pkgs.dockerTools.pullImage {
          inherit (cert-manager-webhook) imageName finalImageName finalImageTag imageDigest os;
          inherit (cert-manager-webhook.${system}) sha256 arch;
        };

        cert-manager-cainjector-image = pkgs.dockerTools.pullImage {
          inherit (cert-manager-cainjector) imageName finalImageName finalImageTag imageDigest os;
          inherit (cert-manager-cainjector.${system}) sha256 arch;
        };

        cert-manager-ctl-image = pkgs.dockerTools.pullImage {
          inherit (cert-manager-ctl) imageName finalImageName finalImageTag imageDigest os;
          inherit (cert-manager-ctl.${system}) sha256 arch;
        };

        csi-node-driver-registrar-image = pkgs.dockerTools.pullImage {
          inherit (csi-node-driver-registrar) imageName finalImageName finalImageTag imageDigest os;
          inherit (csi-node-driver-registrar.${system}) sha256 arch;
        };

        kind-node-image = pkgs.dockerTools.pullImage {
          inherit (kind-node) imageName finalImageName finalImageTag imageDigest os;
          inherit (kind-node.${system}) sha256 arch;
        };

        busybox-image = pkgs.dockerTools.pullImage {
          inherit (busybox) imageName finalImageName finalImageTag imageDigest os;
          inherit (busybox.${system}) sha256 arch;
        };

      in {
        packages = {
          default = containerImage;
          container = containerImage;
          inherit
            cert-manager-helm-chart
            cert-manager-controller-image
            cert-manager-webhook-image
            cert-manager-cainjector-image
            cert-manager-ctl-image
            cert-manager-csi
            csi-node-driver-registrar-image
            kind-node-image
            busybox-image
            csi-lib-e2e;
        };
        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.kubectl
            pkgs.kubernetes-helm
            pkgs.ginkgo
            pkgs.docker
            pkgs.kind
            pkgs.skopeo
            cert-manager-csi
            csi-lib-e2e
          ];
        };
    });
}

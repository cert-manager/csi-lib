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
        pkgs = import nixpkgs { inherit system; };

        # alias for buildGoModule with pinned go version to v1.19;
        buildGo = pkgs.buildGo119Module;

        # We only source go files to have better cache hits when actively
        # working on non-go files.
        src = pkgs.lib.sourceFilesBySuffices ./. [ ".go" "go.mod" "go.sum" ];
        vendorSha256 = "sha256-3pNKmR+yKIf/15eftJyHD7m7LerFbZ2m+N6zxVXz2sU=";

        kindVersion = "v0.15.0";
        kindHash = "sha256-IDSWmNWHnTKOl6/N1Mz+OKOkZSBarpuN39CBsSjYhKY=";
        kindVendorSha256 = "sha256-FE1GvNgXkBt2cH4YB3jTsPXp91DSiYlniQLtMwvi384=";

        cert-manager-csi = buildGo {
          name = "cert-manager-csi";
          inherit src vendorSha256;
          subPackages = [ "./example" ];
          postInstall = "mv $out/bin/example $out/bin/cert-manager-csi";
        };

        # e2e test binary.
        csi-lib-e2e = buildGo {
          name = "csi-lib-e2e";
          inherit src vendorSha256;
          buildPhase = ''
            go test -v --race -o csi-lib-e2e -c ./test/e2e/.
          '';
          postInstall = ''
            mkdir -p $out/bin
            mv csi-lib-e2e $out/bin/.
          '';
          doCheck = false;
        };

        kind = buildGo rec {
          name = "kind";
          version = kindVersion;
          src = pkgs.fetchFromGitHub {
            owner = "kubernetes-sigs";
            repo = name;
            rev = "v${version}";
            hash = kindHash;
          };
          vendorSha256 = kindVendorSha256;
          # Required to ignore `/hack/tools` module.
          subPackages = [ "." ];
          nativeBuildInputs = [ pkgs.installShellFiles ];
          postInstall = ''
            installShellCompletion --cmd kind \
              --bash <($out/bin/kind completion bash) \
              --fish <($out/bin/kind completion fish) \
              --zsh <($out/bin/kind completion zsh)
          '';
          meta = with pkgs.lib; {
            homepage = "https://github.com/kubernetes-sigs/kind";
            description = "Kubernetes IN Docker - local clusters for testing Kubernetes";
            longDescription = ''
              kind is a tool for running local Kubernetes clusters using Docker
              container "nodes". kind was primarily designed for testing Kubernetes
              itself, but may be used for local development or CI.
            '';
            license = licenses.asl20;
          };
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

      in {
        packages = {
          cert-manager-csi = cert-manager-csi;
          csi-lib-e2e = csi-lib-e2e;
          container = containerImage;
          default = containerImage;
        };
        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.kubectl
            pkgs.kubernetes-helm
            pkgs.ginkgo
            pkgs.docker
            kind
            cert-manager-csi
            csi-lib-e2e
          ];
        };
    });
}

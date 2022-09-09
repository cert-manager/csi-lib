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
        pkgs = import nixpkgs {
          inherit system;
          overlays = [

            (final: prev: {
              # Overlay kind to version v0.15.0
              kind = prev.buildGo119Module {
                inherit (prev.kind.drvAttrs)
                  pname doCheck patches nativeBuildInputs buildInputs
                  buildPhase installPhase subPackages postInstall
                  CGO_ENABLED GOFLAGS ldFlags;
                inherit (prev.kind) meta;
                version = "0.15.0";
                src = pkgs.fetchFromGitHub {
                  owner = "kubernetes-sigs";
                  repo = "kind";
                  rev = "v0.15.0";
                  sha256 = "sha256-IDSWmNWHnTKOl6/N1Mz+OKOkZSBarpuN39CBsSjYhKY=";
                };
                vendorSha256 = "sha256-FE1GvNgXkBt2cH4YB3jTsPXp91DSiYlniQLtMwvi384=";
              };
            })
          ];
        };

        # We only source go files to have better cache hits when actively
        # working on non-go files.
        src = pkgs.lib.sourceFilesBySuffices ./. [ ".go" "go.mod" "go.sum" ];
        vendorSha256 = "sha256-3pNKmR+yKIf/15eftJyHD7m7LerFbZ2m+N6zxVXz2sU=";

        cert-manager-csi = pkgs.buildGo119Module {
          name = "cert-manager-csi";
          inherit src vendorSha256;
          subPackages = [ "./example" ];
          postInstall = "mv $out/bin/example $out/bin/cert-manager-csi";
        };

        # e2e test binary.
        csi-lib-e2e = pkgs.buildGo119Module {
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
            pkgs.kind
            cert-manager-csi
            csi-lib-e2e
          ];
        };
    });
}

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
      targetSystems = with flake-utils.lib.system; [
        x86_64-linux
        x86_64-darwin
        aarch64-linux
        aarch64-darwin
      ];

      # We only source go files to have better cache hits when actively
      # working on non-go files.
      src = nixpkgs.lib.sourceFilesBySuffices ./. [ ".go" "go.mod" "go.sum" ];
      vendorSha256 = "sha256-jxiwax8g+ZtiR66UFUfMt5QQ7lGAH6wR3iPugmFZ/hc=";

      src-e2e = nixpkgs.lib.sourceFilesBySuffices ./test/e2e [ ".go" "go.mod" "go.sum" ];
      csi-lib-e2e-vendorSha256 = "sha256-AlovNqQCh+Yvw0Y6zRc24mzLqxMobjjip7Yhi004ROM=";

    in flake-utils.lib.eachSystem targetSystems (system:
      let
        pkgs = import nixpkgs { inherit system; };

        # cert-manager-csi is the build of the example driver using the current
        # source.
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

        # csi-lib container containing the example driver build.
        container = pkgs.dockerTools.buildImage {
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

        # e2e-deps contains all the necessary dependencies to run the e2e
        # tests.
        e2e-deps = import ./hack/nix/e2e-deps.nix { inherit pkgs flake-utils system; };

      in {
        packages = {
          default = container;
          inherit container cert-manager-csi csi-lib-e2e;
        } // e2e-deps.images // e2e-deps.helm-charts; # Merge e2e dependancies map to packages.

        # mkShell is able to setup the nix shell environment (`$ nix develop`).
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

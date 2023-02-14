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
    cert-manager.url = "github:joshvanl/cm-nixpkgs";
    cert-manager.inputs.nixpkgs.follows = "nixpkgs";
    cert-manager.inputs.flake-utils.follows = "flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, cert-manager }:
    let
      targetSystems = with flake-utils.lib.system; [
        x86_64-linux
        x86_64-darwin
        aarch64-linux
        aarch64-darwin
      ];

      repo = ./.;

      # We only source go files to have better cache hits when actively
      # working on non-go files.
      src = nixpkgs.lib.sourceFilesBySuffices ./. [ ".go" "go.mod" "go.sum" ];
      vendorSha256 = "sha256-yQ0MzlVIq57bm20T8VrDPZpJkhaN1Hh7eRo4j1zOgAI=";

      src-e2e = nixpkgs.lib.sourceFilesBySuffices ./test/e2e [ ".go" "go.mod" "go.sum" ];
      csi-lib-e2e-vendorSha256 = "sha256-AlovNqQCh+Yvw0Y6zRc24mzLqxMobjjip7Yhi004ROM=";

    in flake-utils.lib.eachSystem targetSystems (system:
      let
        pkgs = import nixpkgs { inherit system; };
        pkgs-x86-linux = import nixpkgs { system = "x86_64-linux"; };
        cmpkgs = cert-manager.packages.${system};

        # cert-manager-csi is the build of the example driver using the current
        # source.
        cert-manager-csi = pkgs: pkgs.buildGo119Module {
          name = "cert-manager-csi";
          inherit src vendorSha256;
          subPackages = [ "example" ];
          postInstall = "mv $out/bin/example $out/bin/cert-manager-csi";
        };

        # e2e test binary.
        csi-lib-e2e = pkgs: pkgs.buildGo119Module {
          name = "csi-lib-e2e";
          src = src-e2e;
          vendorSha256 = csi-lib-e2e-vendorSha256;
          # We need to use a custom `buildPhase` so that we can build the e2e
          # binary using `go test` instead of `go build`.
          buildPhase = ''
            go test -v --race -o $GOPATH/bin/csi-lib-e2e -c ./.
          '';
        };

        # csi-lib image containing the example driver build.
        csi-lib-image = pkgs: pkgs.dockerTools.buildImage {
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
            Entrypoint = [ "${cert-manager-csi pkgs}/bin/cert-manager-csi" ];
          };
        };

        test-e2e = import ./hack/nix/e2e.nix {
          pkgs = pkgs-x86-linux;
          cmpkgs = cert-manager.packages.x86_64-linux;
          csi-lib-image = (csi-lib-image pkgs-x86-linux);
          csi-lib-e2e = (csi-lib-e2e pkgs-x86-linux);
        };

      in {
        packages = {
          default = (csi-lib-image pkgs);
          csi-lib-image = (csi-lib-image pkgs);
          cert-manager-csi = (cert-manager-csi pkgs);
          e2e-results = test-e2e;
        };

        checks = {
          # Here we are wrapping the test-e2e results. We do this because we
          # _always_ want the test-e2e to _build_ so that we can capture the
          # results of the tests when there is a failure. Here we do the actual
          # exit failure, whilst printing the logs. Useful for CI. use `$ flake
          # build .#e2e-result` to see the logs from your terminal.
          e2e = pkgs.runCommand "csi-lib-e2e" {} ''
            cp -r ${test-e2e} $out;
            cat ${test-e2e}/test-results.log && exit $(cat ${test-e2e}/test-results.code);
          '';
        };

        # mkShell is able to setup the nix shell environment (`$ nix develop`).
        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.go
          ];
        };
    });
}

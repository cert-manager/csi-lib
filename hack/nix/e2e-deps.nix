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

{ pkgs, system, flake-utils }:

with pkgs.lib.attrsets;
let
  cert-manager-version = "1.9.1";

  helm-charts = {
    "jetstack/cert-manager" = pkgs.fetchurl {
      url = "https://charts.jetstack.io/charts/cert-manager-v${cert-manager-version}.tgz";
      sha256 = "sha256-Ricxd7XKaTCvgEfNUr8LeEyEgqwELngS0IZDwomGktU=";
    };
  };

  # Container image digest and sha256 can be fetched using the following.
  # Replace the name and tag as appropriate.
  # Note to use both arch "amd64" and "arm64" to get the sha256 for both.
  # $ nix-shell -p nix-prefetch-docker --run "nix-prefetch-docker --image-name quay.io/jetstack/cert-manager-controller --image-tag v1.9.1 --arch amd64 --os linux"
  # $ nix-shell -p nix-prefetch-docker --run "nix-prefetch-docker --image-name quay.io/jetstack/cert-manager-controller --image-tag v1.9.1 --arch arm64 --os linux"
  images-src = {
    "jetstack/cert-manager-controller" = {
      repo = "quay.io";
      finalImageTag = "v${cert-manager-version}";
      imageDigest = "sha256:81a5e25e2ecf63b96d6a0be28348d08a3055ea75793373109036977c24e34cf0";
      sha256 = {
        amd64 = "0k7kv02zy456n3fg5d4k1ysl7jnrr5k11249pxdwf5xdxayppjz7";
        arm64 = "0h1zsnhshb55cw21x7cvndy3nilar65cdxa2n83zm6qf1a7d6sz8";
      };
    };
    "jetstack/cert-manager-webhook" = {
      repo = "quay.io";
      finalImageTag = "v${cert-manager-version}";
      imageDigest = "sha256:4ab2982a220e1c719473d52d8463508422ab26e92664732bfc4d96b538af6b8a";
      sha256 = {
        amd64 = "0gg404ypk9drjmmm0bfws5p20433bvgail7181bljlxdprywsck1";
        arm64 = "06qdf6aplkk7klszp62rf3my6drwdinpp8c3drnamr45b828b69v";
      };
    };
    "jetstack/cert-manager-cainjector" = {
      repo = "quay.io";
      finalImageTag = "v${cert-manager-version}";
      imageDigest = "sha256:df7f0b5186ddb84eccb383ed4b10ec8b8e2a52e0e599ec51f98086af5f4b4938";
      sha256 = {
        amd64 = "1ybl4sca2f2zslxa0rspriln275m30lpzamnad0p9wfh131gnfxd";
        arm64 = "1yskd7scwk3lgiz1f9akpgp073856yi4z3njpfvg1kw7c91dnr1l";
      };
    };
    "jetstack/cert-manager-ctl" = {
      repo = "quay.io";
      finalImageTag = "v${cert-manager-version}";
      imageDigest = "sha256:468c868b2cbae19a5d54d34b6f1c27fe54b0b3988a6d8cab74455f5411d95e96";
      sha256 = {
        amd64 = "1r7a82x6cp936dnp6jlm6k74gkjwmzx23m0bad6j85gycxy7klgw";
        arm64 = "1sjjx0yjagh7m7lav6ymysms6h4pbpwpmp7xqzrdpph4dcq065bh";
      };
    };
    "sig-storage/csi-node-driver-registrar" = {
      repo = "k8s.gcr.io";
      finalImageTag = "v2.5.0";
      imageDigest = "sha256:4fd21f36075b44d1a423dfb262ad79202ce54e95f5cbc4622a6c1c38ab287ad6";
      sha256 = {
        amd64 = "1zb161ak2chhblv1yq86j34l2r2i2fsnk4zsvrwzxrsbpw42wg05";
        arm64 = "0hdjhm69fr9dz4msn3bll250mhwkxzm31k5b7wf3yynibrbanw1c";
      };
    };
    "kindest/node" = {
      finalImageTag = "v1.25.0";
      imageDigest = "sha256:428aaa17ec82ccde0131cb2d1ca6547d13cf5fdabcc0bbecf749baa935387cbf";
      sha256 = {
        amd64 = "1h80nc6r2msgad8wngyb1bvdc470z4w5msz3dgy2syi6yrm0ijdk";
        arm64 = "1wssixpg4bcjl65s1361n41ccr2l3aad9dg1vhp6fvxdvlzj2r60";
      };
    };
    "busybox" = {
      finalImageTag = "latest";
      imageDigest = "sha256:20142e89dab967c01765b0aea3be4cec3a5957cc330f061e5503ef6168ae6613";
      sha256 = {
        amd64 = "01rjvdi19287bqgl19wmkp4srn49xlr8bik8r0fhz7rfmh3lqa1g";
        arm64 = "1yn3fhkii1c2h2d103xg5j1nsh6bszsjp42jnz9mxv5way6ca7yx";
      };
    };
  };

in {
  # Add 'helm/' prefix to name to avoid name collision with images.
  helm-charts = (mapAttrs' (name: value: nameValuePair ("helm/" + name) value) helm-charts);

  # Pull docker images using the images-src map. Construct map where the value
  # is the docker image derivation.
  images = pkgs.lib.mapAttrs (name: image:
    pkgs.dockerTools.pullImage rec {
      inherit (image) finalImageTag imageDigest;
      # If repo attribute defined, prefix image name with it.
      imageName = (image: if builtins.hasAttr "repo" image then "${image.repo}/${name}" else name) image;
      finalImageName = imageName;
      os = "linux";

      # Select the correct docker arch based on the current target
      # system.
      arch = (arch: if
        arch == flake-utils.lib.system.x86_64-linux ||
        arch == flake-utils.lib.system.x86_64-darwin
      then ("amd64") else ("arm64")) system;

      # Select the correct sha256 based on the current target system.
      sha256 = image.sha256.${arch};
  }) images-src;
}

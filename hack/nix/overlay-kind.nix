final: prev: {
  # Overlay kind to version v0.15.0
  kind = prev.buildGo119Module {
    inherit (prev.kind.drvAttrs)
      pname doCheck patches nativeBuildInputs buildInputs
      buildPhase installPhase subPackages postInstall
      CGO_ENABLED GOFLAGS ldFlags;
    inherit (prev.kind) meta;
    version = "0.15.0";
    src = prev.fetchFromGitHub {
      owner = "kubernetes-sigs";
      repo = "kind";
      rev = "v0.15.0";
      sha256 = "sha256-IDSWmNWHnTKOl6/N1Mz+OKOkZSBarpuN39CBsSjYhKY=";
    };
    vendorSha256 = "sha256-FE1GvNgXkBt2cH4YB3jTsPXp91DSiYlniQLtMwvi384=";
  };
}

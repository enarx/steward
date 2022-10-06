{
  description = "Profian Steward";

  inputs.crane.inputs.flake-compat.follows = "flake-compat";
  inputs.crane.inputs.flake-utils.follows = "flake-utils";
  inputs.crane.inputs.nixpkgs.follows = "nixpkgs";
  inputs.crane.url = github:ipetkov/crane;
  inputs.enarx.url = github:enarx/enarx;
  inputs.flake-compat.flake = false;
  inputs.flake-compat.url = github:edolstra/flake-compat;
  inputs.flake-utils.url = github:numtide/flake-utils;
  inputs.nixpkgs.url = github:profianinc/nixpkgs;
  inputs.rust-overlay.inputs.flake-utils.follows = "flake-utils";
  inputs.rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
  inputs.rust-overlay.url = github:oxalica/rust-overlay;

  outputs = {
    self,
    crane,
    enarx,
    flake-utils,
    nixpkgs,
    rust-overlay,
    ...
  }:
    with flake-utils.lib.system;
      flake-utils.lib.eachSystem [
        aarch64-darwin
        aarch64-linux
        powerpc64le-linux
        x86_64-darwin
        x86_64-linux
      ] (
        system: let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [(import rust-overlay)];
          };

          # TODO: Add and use an overlay
          enarxBin = enarx.packages.${system}.default;

          rust = pkgs.rust-bin.fromRustupToolchainFile "${self}/rust-toolchain.toml";

          cargo.toml = builtins.fromTOML (builtins.readFile "${self}/Cargo.toml");
          src =
            pkgs.nix-gitignore.gitignoreRecursiveSource [
              "*.nix"
              "*.yml"
              "/.github"
              "flake.lock"
              "LICENSE"
              "rust-toolchain.toml"
            ]
            self;

          craneLib = (crane.mkLib pkgs).overrideToolchain rust;

          commonArgs = {
            pname = cargo.toml.package.name;
            inherit (cargo.toml.package) version;
            inherit src;
          };

          cargoArtifacts = craneLib.buildDepsOnly commonArgs;

          commonArtifactArgs = commonArgs // {inherit cargoArtifacts;};

          cargoClippy = craneLib.cargoClippy (commonArtifactArgs // {cargoClippyExtraArgs = "--all-targets --workspace -- --deny warnings";});
          cargoFmt = craneLib.cargoFmt commonArtifactArgs;
          cargoNextest = craneLib.cargoNextest commonArtifactArgs;

          buildPackage = extraArgs: craneLib.buildPackage (commonArtifactArgs // extraArgs);
          nativeBin = buildPackage {};
          wasm32WasiBin = buildPackage {
            nativeBuildInputs = [enarxBin];

            CARGO_BUILD_TARGET = "wasm32-wasi";
            CARGO_TARGET_WASM_WASI32_RUNNER = "enarx run --wasmcfgfile ${self}/Enarx.toml";
          };
          x86_64LinuxMuslBin = buildPackage {
            CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
            CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";
          };

          buildImage = bin:
            pkgs.dockerTools.buildImage {
              inherit (cargo.toml.package) name;
              tag = cargo.toml.package.version;
              contents = [
                bin
              ];
              config.Cmd = [cargo.toml.package.name];
              config.Env = ["PATH=${bin}/bin"];
            };
        in {
          formatter = pkgs.alejandra;

          checks.clippy = cargoClippy;
          checks.fmt = cargoFmt;
          checks.nextest = cargoNextest;

          packages =
            {
              default = nativeBin;

              "${cargo.toml.package.name}" = nativeBin;
              "${cargo.toml.package.name}-x86_64-unknown-linux-musl" = x86_64LinuxMuslBin;
              "${cargo.toml.package.name}-x86_64-unknown-linux-musl-oci" = buildImage x86_64LinuxMuslBin;
            }
            # TODO: Remove once an overlay is created in enarx
            // (pkgs.lib.optionalAttrs (system != powerpc64le-linux) {
              "${cargo.toml.package.name}-wasm32-wasi" = wasm32WasiBin;
            });

          devShells.default = pkgs.mkShell {
            buildInputs =
              [
                pkgs.openssl
                pkgs.wasmtime

                rust
              ]
              # TODO: Add Enarx, once an overlay is created in enarx
              ++ (pkgs.lib.optional (system != powerpc64le-linux) enarxBin);
          };
        }
      );
}

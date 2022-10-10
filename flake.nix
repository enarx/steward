{
  description = "Profian Steward";

  inputs.crane.inputs.flake-compat.follows = "flake-compat";
  inputs.crane.inputs.flake-utils.follows = "flake-utils";
  inputs.crane.inputs.nixpkgs.follows = "nixpkgs";
  inputs.crane.url = github:ipetkov/crane;
  inputs.enarx.url = github:rvolosatovs/enarx/build/crane; # TODO: Remove fork once https://github.com/enarx/enarx/pull/2269 is merged
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
    with flake-utils.lib.system; let
      version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package.version;

      overlay = final: prev: let
        src =
          final.nix-gitignore.gitignoreRecursiveSource [
            "*.nix"
            "*.yml"
            "/.github"
            "flake.lock"
            "LICENSE"
            "rust-toolchain.toml"
          ]
          ./.;

        rustToolchain = prev.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

        craneLib = (crane.mkLib final).overrideToolchain rustToolchain;

        commonArgs = {
          inherit
            src
            version
            ;
          pname = "steward";
        };

        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        commonArtifactArgs = commonArgs // {inherit cargoArtifacts;};

        checks.clippy = craneLib.cargoClippy (commonArtifactArgs // {cargoClippyExtraArgs = "--all-targets --workspace -- --deny warnings";});
        checks.fmt = craneLib.cargoFmt commonArtifactArgs;
        checks.nextest = craneLib.cargoNextest commonArtifactArgs;

        buildPackage = extraArgs:
          craneLib.buildPackage (commonArtifactArgs
            // {
              cargoExtraArgs = "-j $NIX_BUILD_CORES";
            }
            // extraArgs);

        nativeBin = buildPackage {};
        aarch64LinuxMuslBin = buildPackage {
          CARGO_BUILD_TARGET = "aarch64-unknown-linux-musl";
          CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";
        };
        wasm32WasiBin = buildPackage {
          nativeBuildInputs = [final.enarx];

          CARGO_BUILD_TARGET = "wasm32-wasi";
          CARGO_TARGET_WASM_WASI32_RUNNER = "enarx run --wasmcfgfile ${self}/Enarx.toml";
        };
        x86_64LinuxMuslBin = buildPackage {
          CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
          CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";
        };

        buildImage = bin:
          final.dockerTools.buildImage {
            name = "steward";
            tag = version;
            contents = [
              bin
            ];
            config.Cmd = ["steward"];
            config.Env = ["PATH=${bin}/bin"];
          };
      in {
        steward = nativeBin;
        steward-aarch64-unknown-linux-musl = aarch64LinuxMuslBin;
        steward-aarch64-unknown-linux-musl-oci = buildImage aarch64LinuxMuslBin;
        steward-wasm32-wasi = wasm32WasiBin;
        steward-x86_64-unknown-linux-musl = x86_64LinuxMuslBin;
        steward-x86_64-unknown-linux-musl-oci = buildImage x86_64LinuxMuslBin;

        stewardChecks = checks;
        stewardRustToolchain = rustToolchain;
      };
    in
      {
        overlays.default = overlay;
      }
      // flake-utils.lib.eachSystem [
        aarch64-darwin
        aarch64-linux
        powerpc64le-linux
        x86_64-darwin
        x86_64-linux
      ] (
        system: let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [
              rust-overlay.overlays.default
              enarx.overlays.default
              overlay
            ];
          };
        in {
          formatter = pkgs.alejandra;

          checks = pkgs.stewardChecks;

          packages =
            {
              default = pkgs.steward;
            }
            // pkgs.lib.genAttrs [
              "steward"
              "steward-aarch64-unknown-linux-musl"
              "steward-aarch64-unknown-linux-musl-oci"
              "steward-wasm32-wasi"
              "steward-x86_64-unknown-linux-musl"
              "steward-x86_64-unknown-linux-musl-oci"
            ] (name: pkgs.${name});

          devShells.default = pkgs.mkShell {
            buildInputs = [
              pkgs.enarx
              pkgs.openssl
              pkgs.stewardRustToolchain
              pkgs.wasmtime
            ];
          };
        }
      );
}

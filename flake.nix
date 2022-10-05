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
    flake-utils.lib.eachSystem [
      "aarch64-darwin"
      "aarch64-linux"
      "powerpc64le-linux"
      "x86_64-darwin"
      "x86_64-linux"
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
        buildPackage = extraArgs: craneLib.buildPackage (commonArgs // {inherit cargoArtifacts;} // extraArgs);

        nativeBin = buildPackage {};
        # TODO: Add wasm32-wasi support
        #wasm32WasiBin = buildPackage {
        #  CARGO_BUILD_TARGET = "wasm32-wasi";
        #};
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

        packages."${cargo.toml.package.name}" = nativeBin;
        # TODO: Add wasm32-wasi support
        #packages."${cargo.toml.package.name}-wasm32-wasi" = wasm32WasiBin;
        packages."${cargo.toml.package.name}-x86_64-unknown-linux-musl" = x86_64LinuxMuslBin;
        packages."${cargo.toml.package.name}-x86_64-unknown-linux-musl-oci" = buildImage x86_64LinuxMuslBin;
        packages.default = nativeBin;

        devShells.default = pkgs.mkShell {
          buildInputs =
            [
              pkgs.openssl
              pkgs.wasmtime

              rust
            ]
            # TODO: Add Enarx, once an overlay is created in enarx
            ++ (pkgs.lib.optional (system != "powerpc64le-linux") enarxBin);
        };
      }
    );
}

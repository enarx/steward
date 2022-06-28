{
  description = "Profian Steward";

  inputs.fenix.inputs.nixpkgs.follows = "nixpkgs";
  inputs.fenix.url = github:nix-community/fenix;
  inputs.flake-compat.flake = false;
  inputs.flake-compat.url = github:edolstra/flake-compat;
  inputs.flake-utils.url = github:numtide/flake-utils;
  inputs.nixpkgs.url = github:NixOS/nixpkgs;
  inputs.rust-overlay.inputs.flake-utils.follows = "flake-utils";
  inputs.rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
  inputs.rust-overlay.url = github:oxalica/rust-overlay;

  outputs = {
    self,
    fenix,
    flake-utils,
    nixpkgs,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [];
        };

        devRust = fenix.packages.${system}.fromToolchainFile {file = "${self}/rust-toolchain.toml";};

        cargo.toml = builtins.fromTOML (builtins.readFile "${self}/Cargo.toml");

        buildPackage = targetPkgs: rustTargets: extraArgs: let
          rust = with fenix.packages.${system};
            combine (
              [
                minimal.cargo
                minimal.rustc
              ]
              ++ map (target: targets.${target}.latest.rust-std) rustTargets
            );
        in
          (targetPkgs.makeRustPlatform {
            rustc = rust;
            cargo = rust;
          })
          .buildRustPackage
          (extraArgs
            // {
              inherit (cargo.toml.package) name version;

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

              cargoLock.lockFileContents = builtins.readFile "${self}/Cargo.lock";
            });

        nativeBin = buildPackage pkgs [] {};
        x86_64LinuxMuslBin =
          buildPackage (import nixpkgs {
            inherit system;
            crossSystem = {
              config = "x86_64-unknown-linux-musl";
            };
            overlays = [];
          }) [
            "x86_64-unknown-linux-musl"
          ] {
            meta.mainProgram = cargo.toml.package.name;
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

        packages = {
          "${cargo.toml.package.name}" = nativeBin;
          "${cargo.toml.package.name}-x86_64-unknown-linux-musl" = x86_64LinuxMuslBin;
          "${cargo.toml.package.name}-x86_64-unknown-linux-musl-oci" = buildImage x86_64LinuxMuslBin;
        };
        packages.default = nativeBin;

        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.openssl

            devRust
          ];
        };
      }
    );
}

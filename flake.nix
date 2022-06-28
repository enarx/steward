{
  description = "Profian Steward";

  inputs.cargo2nix.inputs.flake-compat.follows = "flake-compat";
  inputs.cargo2nix.inputs.flake-utils.follows = "flake-utils";
  inputs.cargo2nix.inputs.nixpkgs.follows = "nixpkgs";
  inputs.cargo2nix.inputs.rust-overlay.follows = "rust-overlay";
  inputs.cargo2nix.url = github:cargo2nix/cargo2nix;
  inputs.flake-compat.flake = false;
  inputs.flake-compat.url = github:edolstra/flake-compat;
  inputs.flake-utils.url = github:numtide/flake-utils;
  inputs.nixpkgs.url = github:NixOS/nixpkgs;

  outputs = {
    self,
    cargo2nix,
    flake-utils,
    nixpkgs,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [cargo2nix.overlays.default];
        };

        cargo2nixBin = cargo2nix.packages.${system}.cargo2nix;
        devRust = pkgs.rust-bin.fromRustupToolchainFile "${self}/rust-toolchain.toml";

        cargo.toml = builtins.fromTOML (builtins.readFile "${self}/Cargo.toml");

        mkBin = pkgs:
          (
            (pkgs.rustBuilder.makePackageSet {
              packageFun = import "${self}/Cargo.nix";
              rustVersion = "1.61.0";
              workspaceSrc =
                pkgs.nix-gitignore.gitignoreRecursiveSource [
                  "*.nix"
                  "*.yml"
                  "/.github"
                  "flake.lock"
                  "LICENSE"
                  "rust-toolchain.toml"
                ]
                self;
            })
            .workspace
            ."${cargo.toml.package.name}" {}
          )
          .bin;

        nativeBin = mkBin pkgs;
        x86_64LinuxMuslBin = mkBin (import nixpkgs {
          inherit system;
          crossSystem = {
            config = "x86_64-unknown-linux-musl";
          };
          overlays = [cargo2nix.overlays.default];
        });

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

            cargo2nixBin

            devRust
          ];
        };
      }
    );
}

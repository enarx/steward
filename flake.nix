{
  description = "Profian Steward";

  inputs.enarx.url = github:enarx/enarx;
  # NOTE: https://github.com/rvolosatovs/nixify/commit/e714e8244d3736c6bd3168f4de87f519db4a507c following this commit
  # introduced a bug, once that is fixed the dependency should be unpinned
  inputs.nixify.url = github:rvolosatovs/nixify/e87cbcb1ba3f43dbf99901312c70e6d566a21fb6;

  # Temporary override transitive `nixify` dependencies to benefit from updates.
  inputs.nixify.inputs.nixpkgs.follows = "nixpkgs";
  inputs.nixify.inputs.rust-overlay.follows = "rust-overlay";
  inputs.nixpkgs.url = github:nixos/nixpkgs/nixpkgs-22.05-darwin;
  inputs.rust-overlay.url = github:oxalica/rust-overlay;

  outputs = {
    enarx,
    nixify,
    ...
  }:
    with nixify.lib;
      rust.mkFlake {
        src = ./.;

        ignorePaths = [
          "/.github"
          "/.gitignore"
          "/deny.toml"
          "/Enarx.toml"
          "/flake.lock"
          "/flake.nix"
          "/LICENSE"
          "/README.md"
          "/rust-toolchain.toml"
        ];

        overlays = [
          enarx.overlays.rust
          enarx.overlays.default
        ];

        clippy.allFeatures = true;
        clippy.allTargets = true;
        clippy.deny = ["warnings"];

        withDevShells = {
          devShells,
          pkgs,
          ...
        }:
          extendDerivations {
            buildInputs = [
              pkgs.enarx
              pkgs.openssl
              pkgs.wasmtime
            ];
          }
          devShells;
      };
}

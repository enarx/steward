{
  description = "Profian Steward";

  inputs.enarx.url = github:enarx/enarx;
  inputs.nixify.url = github:rvolosatovs/nixify;

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

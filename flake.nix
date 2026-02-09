{
  description = "poe - auto-annotating debug packets for AI-native debugging";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        rust = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" "clippy" "rustfmt" ];
        };
        rustMinimal = pkgs.rust-bin.stable.latest.minimal;
      in {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "poe";
          version = "0.1.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;

          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.zlib ];

          meta = {
            description = "Auto-annotating debug packets for AI-native debugging";
            homepage = "https://github.com/Jaso1024/poe";
            license = pkgs.lib.licenses.mit;
            mainProgram = "poe";
          };
        };

        devShells.default = pkgs.mkShell {
          nativeBuildInputs = [
            rust
            pkgs.pkg-config
          ];

          buildInputs = [
            pkgs.elfutils
            pkgs.zlib
            pkgs.linuxHeaders
          ];

          RUST_BACKTRACE = "1";
        };
      });
}

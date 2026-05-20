{
  description = "FindMy-Export dev shell";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";

    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    naersk = {
      url = "github:nix-community/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      flake-utils,
      nixpkgs,
      naersk,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };

        naersk' = pkgs.callPackage naersk { };
      in
      rec {
        packages.default = naersk'.buildPackage {
          src = ./.;
          strictDeps = true;
          gitSubmodules = true;

          nativeBuildInputs = with pkgs; [
            perl
            protobuf
          ];
        };

        devShell = pkgs.mkShell {
          buildInputs = with pkgs; [
            cargo
            rustc
            rustfmt
            clippy
            rust-analyzer
          ];

          nativeBuildInputs = with pkgs; [
            protobuf
          ];
        };
      }
    );
}

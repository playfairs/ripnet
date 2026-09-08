{
  description = "Network diagnostics, packet analysis, and load testing toolkit";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nox.url = "github:playfairs/nox/dev";
  };

  outputs =
    {
      self,
      nixpkgs,
      treefmt-nix,
      nox,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      formatterFor =
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        import ./nix/formatter.nix {
          inherit pkgs self treefmt-nix;
        };
    in
    {
      packages = nixpkgs.lib.genAttrs systems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.callPackage ./nix/buildPackage.nix { inherit nox; };
        }
      );

      devShells = nixpkgs.lib.genAttrs systems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            buildInputs = [
              pkgs.ldc
              pkgs.gdb
              nox.packages.${system}.default
              pkgs.pkg-config
              pkgs.libpcap
            ] ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [
              pkgs.valgrind
            ];
          };
        }
      );

      formatter = nixpkgs.lib.genAttrs systems (system: (formatterFor system).wrapper);

      checks = nixpkgs.lib.genAttrs systems (system: {
        formatting = (formatterFor system).check;
      });
    };
}

{
  description = "TinyCrypT Build Environment";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-26.05";
  };

  outputs =
    {
      self,
      nixpkgs,
      ...
    }@inputs:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      binsec = pkgs.ocamlPackages.buildDunePackage {
        pname = "binsec";
        version = "0.11.2";
        duneVersion = "3";
        src = pkgs.fetchFromGitHub {
          owner = "binsec";
          repo = "binsec";
          tag = "0.11.2";
          hash = "sha256-72uAKYb+RWjN2eVhXv5cZkBLiRVOgQD0i5mwabnW0HQ=";
        };
        propagatedBuildInputs = with pkgs.ocamlPackages; [
          menhir
          ocamlgraph
          zarith
          dune-site
          dypgen
          toml
          ounit2
          qcheck
          ppx_inline_test
          unionFind
          ocamlformat
          odoc
          unisim_archisec
        ];
        nativeBuildInputs = with pkgs.ocamlPackages; [
          menhir
          ocamlgraph
          zarith
          dune-site
          dypgen
          toml
          ounit2
          qcheck
          ppx_inline_test
          unionFind
          ocamlformat
          odoc
        ];
        strictDeps = true;
      };
      aphrodite_shl = pkgs.mkShell {
        name = "tct-tooling-env-aphrodite";
        packages = with pkgs; [
          ninja
          meson
          just
          clang-tools
          bear
          tokei
          frama-c
          why3
          zig_0_16
          bitwuzla
          ocamlPackages.findlib
          (python314.withPackages (ps: with ps; [lief]))
        ] ++ [binsec];
      };
    in
    {
      devShells.${system} = {
        default = aphrodite_shl;
      };
    };
}

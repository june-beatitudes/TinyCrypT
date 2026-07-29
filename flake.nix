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
      aphrodite_shl = pkgs.mkShell {
        name = "tct-tooling-env-aphrodite";
        packages = with pkgs; [
          ninja
          meson
          gcc
          clang-tools
          bear
          tokei
          frama-c
          z3
          why3
          valgrind-light
          zig_0_16
        ];
      };
    in
    {
      devShells.${system} = {
        default = aphrodite_shl;
      };
    };
}

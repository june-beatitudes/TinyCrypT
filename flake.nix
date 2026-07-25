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
          valgrind
          bear
          tokei
          cbmc
          zig_0_16
          jq
        ];
      };
    in
    {
      devShells.${system} = {
        default = aphrodite_shl;
      };
    };
}

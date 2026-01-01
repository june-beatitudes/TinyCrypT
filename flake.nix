{
  description = "TinyCrypT Build Environment";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-25.11";
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
      shl = pkgs.mkShell {
        name = "tct-tooling-env";
        packages = with pkgs; [
          ninja
          meson
          gcc
          clang-tools
          gnumake
          valgrind
          bear
          tokei
        ];
      };
    in
    {
      devShells.${system}.default = shl;
    };
}

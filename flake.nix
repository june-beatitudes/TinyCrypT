{
  description = "TinyCrypT Build Environment";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
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
          cmake
          clang
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

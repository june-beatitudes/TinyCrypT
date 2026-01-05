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
        ];
      };
      teiresia_shl = pkgs.mkShell {
        name = "tct-tooling-env-teiresia";
        packages = with pkgs; [
          ninja
          meson
          pkgsCross.aarch64-multiplatform.gcc
          clang-tools
          valgrind
          bear
          tokei
        ];
      };
      demeter_shl = pkgs.mkShell {
        name = "tct-tooling-env-demeter";
        packages = with pkgs; [
          ninja
          meson
          pkgsCross.mips64el-linux-gnuabin32.gcc
          clang-tools
          valgrind
          bear
          tokei
        ];
      };
    in
    {
      devShells.${system} = {
        default = aphrodite_shl;
        teiresia = teiresia_shl;
        demeter = demeter_shl;
      };
    };
}

{
  description = "TinyCrypT Build Environment";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-25.11";
    esp32-overlay.url = "github:mirrexagon/nixpkgs-esp-dev";
  };

  outputs =
    {
      self,
      nixpkgs,
      esp32-overlay,
      ...
    }@inputs:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      pkgs-persephone = import nixpkgs {
        overlays = [ esp32-overlay.overlays.default ];
        inherit system;
        config.permittedInsecurePackages = [ "python3.13-ecdsa-0.19.1" ];
      };
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
          pkgsCross.aarch64-multiplatform-musl.gcc
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
      persephone_shl = pkgs.mkShell {
        name = "tct-tooling-env-persephone";
        packages = with pkgs-persephone; [
          ninja
          meson
          esp-idf-xtensa
          qemu-esp32
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
        persephone = persephone_shl;
      };
    };
}

{
  description = "TinyCrypT Build Environment";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-26.05";
    unity = {
      flake = false;
      url="github:ThrowTheSwitch/Unity";
    };
    wycheproof = {
      flake = false;
      url="github:C2SP/wycheproof";
    };
    musl_cross_flake.url = "git+https://forge.eyes-like-fire.org/juniper/musl-cross-flake.git";
  };

  outputs =
    {
      self,
      nixpkgs,
      musl_cross_flake,
      unity,
      wycheproof,
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
        packages =
          with pkgs;
          [
            ninja
            meson
            just
            clang-tools
            bear
            tokei
            zig_0_16
            ocamlPackages.findlib
            perf
            bitwuzla
            cbmc
            qemu-user
            parallel
            (python314.withPackages (
              ps: with ps; [
                lief
                cryptography
                ninja
              ]
            ))
          ]
          ++ [
            binsec
            (musl_cross_flake.lib.mkMuslCrossCompiler {
              pkgs = pkgs;
              target = "mipsel-linux-muslsf";
              musl_config = "CFLAGS='-march=r5900'";
            })
          ];
      };
    in
    {
      formatter.${system} = pkgs.nixfmt;
      devShells.${system} = {
        default = aphrodite_shl;
      };
      packages.${system}.default = pkgs.stdenv.mkDerivation {
        name = "libtinycrypt";
        version = "0.16.0";
        src = pkgs.nix-gitignore.gitignoreSource [ ] ./.;

        nativeBuildInputs =
          with pkgs;
          [
            ninja
            meson
            just
            zig_0_16
            ocamlPackages.findlib
            bitwuzla
            cbmc
            bash
            which
            ruby
            qemu-user
            parallel
            (python314.withPackages (
              ps: with ps; [
                lief
                cryptography
                ninja
              ]
            ))
          ]
          ++ [
            binsec
            (musl_cross_flake.lib.mkMuslCrossCompiler {
              pkgs = pkgs;
              target = "mipsel-linux-muslsf";
              musl_config = "CFLAGS='-march=r5900'";
            })
          ];

        configurePhase = ''
          cp -r ${unity}/* tests/Unity
          patchShebangs tests/Unity/auto/*.py
          patchShebangs tests/Unity/auto/*.rb

          cp -r ${wycheproof}/* tests/wycheproof
        '';

        buildPhase = ''
          mkdir -p $TMPDIR/.zig-cache-global
          mkdir -p $TMPDIR/.zig-cache-local
          export ZIG_GLOBAL_CACHE_DIR="$TMPDIR/.zig-cache-global";
          export ZIG_LOCAL_CACHE_DIR="$TMPDIR/.zig-cache-local";
          just build-all
        '';

        checkPhase = ''
          mkdir -p $TMPDIR/.zig-cache-global
          mkdir -p $TMPDIR/.zig-cache-local
          export ZIG_GLOBAL_CACHE_DIR="$TMPDIR/.zig-cache-global";
          export ZIG_LOCAL_CACHE_DIR="$TMPDIR/.zig-cache-local";
          just prove-soundness
          just prove-ct
          just test-all
        '';

        doCheck = true;

        installPhase = ''
          mkdir -p $out/x86_64-avx2
          cp build-x86_64-avx2/libtinycrypt.a $out/x86_64-avx2
          mkdir -p $out/x86_64-avx2/include/tinycrypt
          cp tinycrypt/*.h $out/x86_64-avx2/include/tinycrypt
        '';
      };
    };
}

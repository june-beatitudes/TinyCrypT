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
      # Manually fetch and derive the mula library
      mula = pkgs.ocamlPackages.buildDunePackage rec {
        pname = "mula";
        version = "0.1.2";

        src = pkgs.fetchurl {
          url = "https://github.com/ifazk/mula/releases/download/${version}/mula-${version}.tbz";
          sha256 = "1f0ee42aca73e33459796baa26063bf82d290cb6f4c723d3e7c9a0e58f1e0d72";
        };

        # OCaml native dependencies for building/testing
        nativeBuildInputs = [ pkgs.ocamlPackages.ocaml pkgs.ocamlPackages.findlib ];
        buildInputs = [ pkgs.ocamlPackages.dune_3 ];

        meta = {
          description = "ML's Universal Levenshtein Automata library";
          homepage = "https://github.com/ifazk/mula";
        };
      };
      binsec = pkgs.ocamlPackages.buildDunePackage {
        pname = "binsec";
        version = "0.11.3";
        duneVersion = "3";
        src = pkgs.fetchFromGitHub {
          owner = "binsec";
          repo = "binsec";
          tag = "0.11.3";
          hash = "sha256-+A4wFTCORupYuDnS405CO67s05jCqWLM79GM1XGfTVQ=";
        };
        propagatedBuildInputs = (with pkgs.ocamlPackages; [
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
        ]) ++ [mula];
        nativeBuildInputs = (with pkgs.ocamlPackages; [
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
        ]) ++ [mula];
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
          read -r -a TARGET_ARR <<< "$(just list-targets)"
          mkdir -p $out
          for target in "''${TARGET_ARR[@]}"; do
              mkdir -p $TMPDIR/artifacts/$target
              cp build/$target/libtinycrypt.a $TMPDIR/artifacts/$target
              mkdir -p $TMPDIR/artifacts/$target/include/tinycrypt
              mkdir -p $TMPDIR/artifacts/$target/include/tinycrypt/internal
              cp tinycrypt/*.h $TMPDIR/artifacts/$target/include/tinycrypt
              cp tinycrypt/internal/*.h $TMPDIR/artifacts/$target/include/tinycrypt/internal
              tar cjvf $out/$target.tar.xz -C $TMPDIR/artifacts/$target/ .
          done
        '';
      };
    };
}

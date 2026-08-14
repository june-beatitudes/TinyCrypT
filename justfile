targets := `find machines -type f -name *.toml | xargs -- basename -a -s .toml | sed -z "s/\n/ /g"`
target_regex := `find machines -type f -name *.toml | xargs -- basename -a -s .toml | sed -z "s/\n/|/g"`
bash := `which bash`
python3 := `which python3`

list-targets:
    @echo '{{ targets }}'

[working-directory('.')]
build-all:
    #!{{ bash }}
    set -euo pipefail
    read -r -a TARGET_ARR <<< "{{ targets }}"
    for target in "${TARGET_ARR[@]}"; do
        {{ python3 }} build.py . machines/$target.toml
        ninja -C build/$target lib
    done

[working-directory('.')]
test-all:
    #!{{ bash }}
    set -euo pipefail
    read -r -a TARGET_ARR <<< "{{ targets }}"
    supported=()
    for target in "${TARGET_ARR[@]}"; do
        if [[ ! $({{ python3 }} machines/check_props.py machines/$target.toml supports-tests) == "true" ]]; then
            REASON="$({{ python3 }} machines/check_props.py machines/$target.toml tests-disabled-why)"
            echo "Target $target does not support testing ($REASON)."
        else
            ninja -C build/$target tests
        fi
    done

[working-directory('.')]
make-compdb target="x86_64-avx2": (check-exists target)
    {{ python3 }} build.py . machines/{{ target }}.toml
    ninja -C build/{{ target }} -t compdb > compile_commands.json

[working-directory('.')]
build target="x86_64-avx2": (check-exists target)
    @echo 'Building libtinycrypt for target {{ target }}'
    {{ python3 }} build.py . machines/{{ target }}.toml
    ninja -C build/{{ target }} lib

[working-directory('.')]
test target="x86_64-avx2": (check-tests-supported target)
    @echo 'Testing libtinycrypt for target {{ target }}'
    {{ python3 }} build.py . machines/{{ target }}.toml
    ninja -C build/{{ target }} tests

[working-directory('.')]
prove-ct target="x86_64-avx2": (check-binsec-supported target)
    @echo 'Running libtinycrypt constant-time proof for target {{ target }}'
    zig cc proofs/binsec/x25519/harness.c build-{{ target }}/libtinycrypt.a -o test -I. -static -target x86_64-linux-musl
    binsec -sse -checkct -sse-script proofs/binsec/x25519/binsec.cfg ./test -sse-depth 2000000
    zig cc proofs/binsec/sha2/harness.c build-{{ target }}/libtinycrypt.a -o test -I. -static -target x86_64-linux-musl
    binsec -sse -checkct -sse-script proofs/binsec/sha2/binsec.cfg ./test -sse-depth 2000000

[working-directory('.')]
prove-soundness:
    @echo "Running all libtinycrypt soundness proofs"
    mkdir -p build-soundness/sha3
    python3 proofs/cbmc/create_ninja.py $(pwd) proofs/cbmc/sha3/manifest.toml $(pwd)/build-soundness/sha3 $(pwd)
    ninja -C build-soundness/sha3

[working-directory('.')]
check-exists target:
    #!{{ bash }}
    set -euo pipefail

    if [[(! "{{ target }}" =~ ^({{ target_regex }})$) || (-z "{{ target }}")]]; then
        echo "Target not supported. Use 'just list-targets' for a list of supported targets."
        exit 1
    fi

[working-directory('.')]
check-binsec-supported target: (check-exists target)
    #!{{ bash }}
    set -euo pipefail

    if [[ ! $({{ python3 }} machines/check_props.py machines/{{ target }}.toml supports-binsec) == "true" ]]; then
        REASON="$({{ python3 }} machines/check_props.py machines/{{ target }}.toml binsec-disabled-why)"
        echo "Target {{ target }} does not support BINSEC analysis ($REASON)."
        exit 1
    fi

[working-directory('.')]
check-tests-supported target: (check-exists target)
    #!{{ bash }}
    set -euo pipefail

    if [[ ! $({{ python3 }} machines/check_props.py machines/{{ target }}.toml supports-tests) == "true" ]]; then
        REASON="$({{ python3 }} machines/check_props.py machines/{{ target }}.toml tests-disabled-why)"
        echo "Target {{ target }} does not support testing ($REASON)."
        exit 1
    fi

[working-directory('.')]
cleanall:
    #!{{ bash }}
    set -euo pipefail

    echo 'Cleaning repo'
    for target in `echo '{{ targets }}' | sed 's/|/\n/g'`
    do
        if [[ -d "build-${target}" ]]; then
            ninja -C build-${target} -t clean
        fi
    done

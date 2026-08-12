targets := `find machines -type f | awk -F'[/.]' '{print $2}' | sed -z 's/\n/|/g'`
bash := `which bash`

list-targets:
    @echo '{{ targets }}'

[working-directory('.')]
build target="x86_64-avx2": (check-supported target)
    @echo 'Building libtinycrypt for target {{ target }}'
    meson setup --cross-file $(pwd)/machines/{{ target }}.ini build-{{ target }}
    ninja -C build-{{ target }} libtinycrypt.a
    cp build-{{ target }}/compile_commands.json .

[working-directory('.')]
test target="x86_64-avx2": (check-supported target)
    @echo 'Testing libtinycrypt for target {{ target }}'
    cd build-{{ target }} && meson test --timeout 10

[working-directory('.')]
prove-ct target="x86_64-avx2": (check-supported target)
    @echo 'Running libtinycrypt constant-time proof for target {{ target }}'
    zig cc proofs/x25519/harness.c build-{{ target }}/libtinycrypt.a -o test -I.
    binsec -sse -checkct -sse-script proofs/x25519/binsec.cfg ./test -sse-depth 2000000

[working-directory('.')]
prove-soundness:
    @echo "Running all libtinycrypt soundness proofs"
    mkdir -p build-soundness
    python3 proofs/cbmc/create_ninja.py $(pwd) proofs/cbmc/sha3/manifest.toml $(pwd)/build-soundness $(pwd)
    ninja -C build-soundness

[working-directory('.')]
check-supported target:
    #!{{ bash }}
    set -euo pipefail

    if [[(! "{{ target }}" =~ ^({{ targets }})$) || (-z "{{ target }}")]]; then
        echo "Target not supported. Use 'just list-targets' for a list of supported targets."
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

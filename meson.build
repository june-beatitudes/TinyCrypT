project('TinyCrypT', 'c', version: '0.1.0')

incdir = include_directories('tinycrypt')

sources = [
    'tinycrypt/chacha20-poly1305.c',
    'tinycrypt/kangarootwelve128.c',
    'tinycrypt/sha2.c',
    'tinycrypt/x25519.c',
]

if meson.get_compiler('c').has_define('__SIZEOF_INT128__')
    sources += 'tinycrypt/ed25519_64bit.c'
else
    sources += 'tinycrypt/ed25519.c'
endif

build_args = [
    '-O3',
    '-ffreestanding',
]

target = static_library('tinycrypt', sources, c_args: build_args, include_directories: incdir)

project_dep = declare_dependency(
  include_directories: incdir,
  link_with : target
)
set_variable(meson.project_name() + '_dep', project_dep)

sha2_test_sources = [
    'tests/src/sha2/SHA512LongMsg.cpp',
    'tests/src/sha2/SHA512ShortMsg.cpp',
    'tests/src/sha2/SHA512Monte.cpp',
    'tests/src/sha2/SHA256LongMsg.cpp',
    'tests/src/sha2/SHA256ShortMsg.cpp',
    'tests/src/sha2/SHA256Monte.cpp',
]

ed25519_test_sources = [
    'tests/src/ed25519/verify_happy.cpp',
    'tests/src/ed25519/verify_sad.cpp',
    'tests/src/ed25519/sign.cpp',
    'tests/src/ed25519/keygen.cpp',
]

if not meson.is_subproject() and not meson.is_cross_build()
    add_languages('cpp')
    subdir('tests')
    test(
        'sha2_tests',
        executable(
            'sha2_tests',
            sha2_test_sources,
            include_directories: incdir,
            link_with: target,
            dependencies: test_dep,
            install: false
        )
    )
    test(
        'ed25519_tests',
        executable(
            'ed25519_tests',
            ed25519_test_sources,
            include_directories: incdir,
            link_with: target,
            dependencies: test_dep,
            install: false
        )
    )
endif
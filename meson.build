project('TinyCrypT', 'c', version: '0.1.0')

incdir = include_directories('tinycrypt')

sources = [
    'tinycrypt/portable/kangarootwelve128.c',
    'tinycrypt/portable/sha2.c',
]

if meson.get_compiler('c').has_define('__SIZEOF_INT128__')
    sources += 'tinycrypt/x86_64_aarch64/ed25519.c'
else
    sources += 'tinycrypt/portable/ed25519.c'
endif

if meson.get_compiler('c').has_define('__SIZEOF_INT128__')
    sources += 'tinycrypt/x86_64_aarch64/chacha20_poly1305.c'
else
    sources += 'tinycrypt/portable/chacha20_poly1305.c'
endif

if meson.get_compiler('c').has_define('__SIZEOF_INT128__')
    sources += 'tinycrypt/x86_64_aarch64/x25519.c'
else
    sources += 'tinycrypt/portable/x25519.c'
endif

build_args = [
    '-O3',
    '-ffreestanding',
]

if target_machine.cpu_family() == 'x86_64'
    build_args += '-march=native'
endif

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

cc20_p1305_test_sources = [
    'tests/src/chacha20-poly1305/all.cpp',
]

x25519_test_sources = [
    'tests/src/x25519/all.cpp',
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
    test(
        'cc20_p1305_tests',
        executable(
            'cc20_p1305_tests',
            cc20_p1305_test_sources,
            include_directories: incdir,
            link_with: target,
            dependencies: test_dep,
            install: false
        )
    )
    # Not included by default because it takes ~256 seconds to execute (includes a million-repetition test case)
    # test(
    #     'x25519_tests',
    #     executable(
    #         'x25519_tests',
    #         x25519_test_sources,
    #         include_directories: incdir,
    #         link_with: target,
    #         dependencies: test_dep,
    #         install: false
    #     )
    # )
endif
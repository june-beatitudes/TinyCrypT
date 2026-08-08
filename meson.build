project('TinyCrypT', 'c', version: '0.16.0', meson_version: '>=1.3.0')

incdir = include_directories('.')

sources = [
  'tinycrypt/portable/sha3.c',
  'tinycrypt/portable/sha2.c',
]

if meson.get_compiler('c').has_define('__SIZEOF_INT128__')
  sources += 'tinycrypt/min64/ed25519.c'
else
  sources += 'tinycrypt/min32/ed25519.c'
endif

if meson.get_compiler('c').has_define('__SIZEOF_INT128__')
  sources += 'tinycrypt/min64/chacha20_poly1305.c'
else
  sources += 'tinycrypt/min32/chacha20_poly1305.c'
endif

if meson.get_compiler('c').has_define('__SIZEOF_INT128__')
  sources += 'tinycrypt/min64/x25519.c'
else
  sources += 'tinycrypt/min32/x25519.c'
endif

build_args = [
  '-O3',
  '-ffreestanding',
  '-fno-sanitize=all',
  '-Wall',
  '-Werror',
  '-std=c99',
]

if get_option('memconstrained')
  build_args += '-DTCT_LOWMEM'
endif

if get_option('simd') == '256-bit'
  build_args += '-DTCT_SIMD128'
  build_args += '-DTCT_SIMD256'
elif get_option('simd') == '128-bit'
  build_args += '-DTCT_SIMD128'
endif

if get_option('simd') == 'none'
  sources += 'tinycrypt/portable/chacha20-scalar.c'
else
  sources += 'tinycrypt/portable/chacha20-simd.c'
  build_args += '-DTCT_SIMD'
endif

if target_machine.cpu_family() == 'x86_64'
  if get_option('simd') == '256-bit'
    build_args += '-mavx2'
  else
    build_args += '-mno-avx2'
  endif
endif

if target_machine.endian() == 'little'
  build_args += '-DTCT_LITTLE_ENDIAN'
endif

target = static_library('tinycrypt', sources, c_args: build_args, include_directories: incdir)

project_dep = declare_dependency(include_directories: incdir, link_with: target)
set_variable(meson.project_name() + '_dep', project_dep)

python = find_program('python3')

if not meson.is_subproject() and meson.can_run_host_binaries()
  unity_proj = subproject('Unity')
  unity_dep = unity_proj.get_variable('unity_dep')
  unity_gen_test_runner = unity_proj.get_variable('gen_test_runner')

  # Note that all the script cares about is the directory the rsp file is in, not which one it is
  sha2_test_file = custom_target(
    'nist_sha2_test_file',
    input: [
      'tests/src/sha2/testgen.py',
      'tests/src/sha2/SHA256LongMsg.rsp',
    ],
    output: 'nist_sha2_tests.autogen.c',
    command: [python, '@INPUT@', '@OUTPUT@'],
  )
  sha2_test_sources = [sha2_test_file, unity_gen_test_runner.process(sha2_test_file)]

  # See comment above
  sha3_test_file = custom_target(
    'nist_sha3_test_file',
    input: [
      'tests/src/sha3/testgen.py',
      'tests/src/sha3/SHAKE128LongMsg.rsp',
    ],
    output: 'nist_sha3_tests.autogen.c',
    command: [python, '@INPUT@', '@OUTPUT@'],
  )
  sha3_test_sources = [sha3_test_file, unity_gen_test_runner.process(sha3_test_file)]

  fuzz_test_file = custom_target(
    'fuzz_test_file',
    input: 'tests/src/fuzzing.py',
    output: 'fuzzing_tests.autogen.c',
    command: [python, '@INPUT@', '@OUTPUT@'],
  )
  fuzz_test_sources = [fuzz_test_file, unity_gen_test_runner.process(fuzz_test_file)]

  libgcrypt_test_file = custom_target(
    'libgcrypt_ed25519_test_file',
    input: [
      'tests/src/ed25519/libgcrypt_testgen.py',
      'tests/src/ed25519/libgcrypt_tests.inp',
    ],
    output: 'libgcrypt_ed25519_tests.autogen.c',
    command: [python, '@INPUT@', '@OUTPUT@'],
  )
  ed25519_libgcrypt_sources = [
    libgcrypt_test_file,
    unity_gen_test_runner.process(libgcrypt_test_file),
  ]
  test(
    'ed25519_libgcrypt_tests',
    executable(
      'ed25519_libgcrypt_tests',
      ed25519_libgcrypt_sources,
      include_directories: incdir,
      link_with: target,
      dependencies: unity_dep,
      install: false,
    ),
  )

  ed25519_wycheproof_test_file = custom_target(
    'wycheproof_ed25519_test_file',
    input: [
      'tests/src/ed25519/wycheproof_testgen.py',
      'tests/wycheproof/testvectors_v1/ed25519_test.json',
    ],
    output: 'wycheproof_ed25519_tests.autogen.c',
    command: [python, '@INPUT@', '@OUTPUT@'],
  )
  ed25519_wycheproof_sources = [
    ed25519_wycheproof_test_file,
    unity_gen_test_runner.process(ed25519_wycheproof_test_file),
  ]
  test(
    'ed25519_wycheproof_tests',
    executable(
      'ed25519_wycheproof_tests',
      ed25519_wycheproof_sources,
      include_directories: incdir,
      link_with: target,
      dependencies: unity_dep,
      install: false,
    ),
  )

  cc20_p1305_test_sources = [
    'tests/src/chacha20-poly1305/all.c',
    unity_gen_test_runner.process('tests/src/chacha20-poly1305/all.c'),
  ]
  test(
    'cc20_p1305_tests',
    executable(
      'cc20_p1305_tests',
      cc20_p1305_test_sources,
      include_directories: incdir,
      link_with: target,
      dependencies: unity_dep,
      install: false,
    ),
  )

  x25519_rfc_sources = [
    'tests/src/x25519/rfc.c',
    unity_gen_test_runner.process('tests/src/x25519/rfc.c'),
  ]
  x25519_wycheproof_sources = [
    'tests/src/x25519/wycheproof.c',
    unity_gen_test_runner.process('tests/src/x25519/wycheproof.c'),
  ]
  test(
    'x25519_rfc_tests',
    executable(
      'x25519_rfc_tests',
      x25519_rfc_sources,
      include_directories: incdir,
      link_with: target,
      dependencies: unity_dep,
      install: false,
    ),
  )
  test(
    'x25519_wycheproof_tests',
    executable(
      'x25519_wycheproof_tests',
      x25519_wycheproof_sources,
      include_directories: incdir,
      link_with: target,
      dependencies: unity_dep,
      install: false,
    ),
  )
  test(
    'sha2_tests',
    executable(
      'sha2_tests',
      sha2_test_sources,
      include_directories: incdir,
      link_with: target,
      dependencies: unity_dep,
      install: false,
    ),
  )
  test(
    'sha3_tests',
    executable(
      'sha3_tests',
      sha3_test_sources,
      include_directories: incdir,
      link_with: target,
      dependencies: unity_dep,
      install: false,
    ),
  )
  test(
    'fuzz_tests',
    executable(
      'fuzz_tests',
      fuzz_test_sources,
      include_directories: incdir,
      link_with: target,
      dependencies: unity_dep,
      install: false,
    ),
  )
endif

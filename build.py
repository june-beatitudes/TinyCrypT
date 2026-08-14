import pathlib
import sys

import tomllib
from ninja import ninja_syntax

LIB_BASE_CFLAGS = [
    "-ffreestanding",
    "-fno-sanitize=all",
    "-Wall",
    "-Werror",
    "-O3",
    "-ffunction-sections",
    "-fdata-sections",
]

TEST_BASE_CFLAGS = []

TEST_BASE_LINKFLAGS = ["-Wl,--gc-sections"]


def get_relevant_lib_sources(machine_manifest: dict) -> list[str]:
    sources = ["tinycrypt/portable/sha2.c", "tinycrypt/portable/sha3.c"]
    if machine_manifest["machine"]["has_uint128"]:
        sources += [
            "tinycrypt/min64/chacha20_poly1305.c",
            "tinycrypt/min64/ed25519.c",
            "tinycrypt/min64/x25519.c",
        ]
    else:
        sources += [
            "tinycrypt/min32/chacha20_poly1305.c",
            "tinycrypt/min32/ed25519.c",
            "tinycrypt/min32/x25519.c",
        ]

    if len(machine_manifest["machine"]["simd_widths"]) > 0:
        sources += ["tinycrypt/portable/chacha20-simd.c"]
    else:
        sources += ["tinycrypt/portable/chacha20-scalar.c"]
    return sources


def get_relevant_lib_defines(machine_manifest: dict) -> list[str]:
    defs = []
    if machine_manifest["machine"]["mem_constrained"]:
        defs.append("TCT_LOWMEM")
    if len(machine_manifest["machine"]["simd_widths"]) > 0:
        defs.append("TCT_SIMD")
        defs += [
            f"TCT_SIMD{width}" for width in machine_manifest["machine"]["simd_widths"]
        ]
    if machine_manifest["machine"]["endian"] == "little":
        defs.append("TCT_LITTLE_ENDIAN")
    return defs


def gen_test_rules(
    writer: ninja_syntax.Writer,
    base_dir: pathlib.Path,
    output_dir: pathlib.Path,
    lib_archive: pathlib.Path,
):
    sources = [
        base_dir.joinpath(subpath)
        for subpath in ["tests/src/chacha20-poly1305/all.c", "tests/src/x25519/rfc.c"]
    ]
    writer.rule("test_gen", "$python3 $generator $in $out")
    generators = [
        (
            "tests/src/ed25519/libgcrypt_testgen.py",
            "tests/src/ed25519/libgcrypt_tests.inp",
            "ed25519_libgcrypt_tests.autogen.c",
        ),
        (
            "tests/src/ed25519/wycheproof_testgen.py",
            "tests/wycheproof/testvectors_v1/ed25519_test.json",
            "ed25519_wycheproof_tests.autogen.c",
        ),
        (
            "tests/src/fuzzing.py",
            None,
            "fuzzing_tests.autogen.c",
        ),
        (
            "tests/src/sha3/testgen.py",
            "tests/src/sha3/SHAKE128LongMsg.rsp",
            "nist_sha3_tests.autogen.c",
        ),
        (
            "tests/src/sha2/testgen.py",
            "tests/src/sha2/SHA256LongMsg.rsp",
            "nist_sha2_tests.autogen.c",
        ),
    ]
    logfiles = []
    UNITY = output_dir.joinpath("unity.o").absolute()
    writer.build(
        str(UNITY), "test_compile", str(base_dir.joinpath("tests/Unity/src/unity.c"))
    )
    for autogen in generators:
        GENERATED = output_dir.joinpath(autogen[2]).absolute()
        writer.build(
            str(GENERATED),
            "test_gen",
            str(base_dir.joinpath(autogen[1]).absolute())
            if autogen[1] is not None
            else "",
            variables={"generator": str(base_dir.joinpath(autogen[0]).absolute())},
        )
        sources.append(GENERATED)
    for source in sources:
        RUNNER = str(output_dir.joinpath(f"{source.stem}.runner.c"))
        OBJFILE = str(output_dir.joinpath(f"{source.stem}.o"))
        LOGFILE = str(output_dir.joinpath(f"{source.stem}.log"))
        writer.build(
            RUNNER,
            "test_genrunner",
            str(source),
        )
        writer.build(f"{RUNNER}.o", "test_compile", RUNNER)
        writer.build(OBJFILE, "test_compile", str(source))
        writer.build(
            f"{RUNNER}.exe",
            "test_link",
            [OBJFILE, str(UNITY), f"{RUNNER}.o", str(lib_archive)],
        )
        writer.build(LOGFILE, "test_run", f"{RUNNER}.exe")
        logfiles.append(LOGFILE)
    writer.build("tests", "phony", logfiles)


def main():
    BASE_DIR = pathlib.Path(sys.argv[1]).absolute()
    assert BASE_DIR.exists() and BASE_DIR.is_dir()
    BUILD_DIR = BASE_DIR.joinpath("build")
    BUILD_DIR.mkdir(parents=True, exist_ok=True)

    MACHINE_MANIFEST_PATH = pathlib.Path(sys.argv[2]).absolute()
    assert MACHINE_MANIFEST_PATH.exists() and MACHINE_MANIFEST_PATH.is_file()
    with open(MACHINE_MANIFEST_PATH, "rb") as manifest_file:
        machine_manifest = tomllib.load(manifest_file)

    OUTPUT_DIR = BUILD_DIR.joinpath(machine_manifest["meta"]["name"])
    OUTPUT_DIR.mkdir(exist_ok=True)
    OBJ_DIR = OUTPUT_DIR.joinpath("objs")
    OBJ_DIR.mkdir(exist_ok=True)
    TEST_DIR = OUTPUT_DIR.joinpath("tests")
    TEST_DIR.mkdir(exist_ok=True)

    sources = get_relevant_lib_sources(machine_manifest)

    with open(OUTPUT_DIR.joinpath("build.ninja"), "w") as ninja_file:
        writer = ninja_syntax.Writer(ninja_file)
        writer.variable("cc", " ".join(machine_manifest["compiling"]["cc"]))
        writer.variable("ar", " ".join(machine_manifest["compiling"]["ar"]))
        writer.variable("python3", "python3")
        writer.variable("ruby", "ruby")
        if machine_manifest["testing"]["enabled"]:
            writer.variable("run", machine_manifest["testing"]["wrapper"])

        writer.rule(
            "lib_compile",
            f"$cc \
                $in \
                -o $out \
                -c \
                -I{BASE_DIR} \
                {' '.join(set(machine_manifest['compiling']['cflags'] + LIB_BASE_CFLAGS + ['-D' + define for define in get_relevant_lib_defines(machine_manifest)]))}",
        )
        if machine_manifest["testing"]["enabled"]:
            writer.rule(
                "test_genrunner",
                f"$ruby {BASE_DIR.joinpath('tests/Unity/auto/generate_test_runner.rb')} $in $out",
            )
            writer.rule(
                "test_compile",
                f"$cc \
                    $in \
                    -o $out \
                    -c \
                    -I{BASE_DIR} \
                    -I{BASE_DIR.joinpath('tests/Unity/src')} \
                    {' '.join(set(machine_manifest['testing']['cflags'] + TEST_BASE_CFLAGS))}",
            )
            writer.rule(
                "test_link",
                f"$cc \
                    $in \
                    -o $out \
                    {' '.join(set(machine_manifest['testing']['cflags'] + TEST_BASE_LINKFLAGS))}",
            )
            writer.rule("test_run", "$run $in > $out")
        writer.rule("lib_archive", "$ar rcs $out $in")

        lib_objs = []
        for source in sources:
            BASE_NAME = BASE_DIR.joinpath(source).stem
            OBJ_PATH = str(OBJ_DIR.joinpath(f"{BASE_NAME}.o").absolute())
            lib_objs.append(OBJ_PATH)
            writer.build(
                OBJ_PATH,
                "lib_compile",
                str(BASE_DIR.joinpath(source).absolute()),
            )
        ARCHIVE_PATH = OUTPUT_DIR.joinpath("libtinycrypt.a").absolute()
        writer.build(
            str(ARCHIVE_PATH),
            "lib_archive",
            lib_objs,
        )
        writer.build("lib", "phony", str(ARCHIVE_PATH))
        if machine_manifest["testing"]["enabled"]:
            gen_test_rules(writer, BASE_DIR, OBJ_DIR, ARCHIVE_PATH)


if __name__ == "__main__":
    main()

import pathlib
import sys

import tomllib
from ninja import ninja_syntax

assert (
    len(sys.argv) > 4
)  # Need to provide include path, manifest, output path, and source files in that order

INCLUDE_PATH = pathlib.Path(sys.argv[1])
MANIFEST_PATH = pathlib.Path(sys.argv[2])
OUTPUT_PATH = pathlib.Path(sys.argv[3])
BASE_PATH = pathlib.Path(sys.argv[4])

with (
    open(OUTPUT_PATH.joinpath("build.ninja"), "w") as of,
    open(MANIFEST_PATH, "rb") as manifest,
):
    manifest_vars = tomllib.load(manifest)
    writer = ninja_syntax.Writer(of)

    writer.variable("gotocc", "goto-cc")
    writer.variable("gotoinstr", "goto-instrument")
    writer.variable("cbmc", "cbmc")

    writer.rule(
        "compile",
        f"$gotocc $in -o $out --function harness $cflags -I{INCLUDE_PATH}",
    )
    writer.rule(
        "instrument",
        "$gotoinstr \
            --dfcc harness \
            $apply_loop_contracts \
            $enforce_contracts \
            $replace_calls_with_contracts \
            $in $out",
    )
    writer.rule(
        "prove",
        "$cbmc $in \
            --object-bits $object_bits \
            --unwinding-assertions \
            --pointer-check \
            --bounds-check \
            --conversion-check \
            --pointer-overflow-check \
            --unsigned-overflow-check \
            --stop-on-fail > $out",
    )

    for proof in manifest_vars["proofs"]:
        writer.build(
            f"{proof}.goto",
            "compile",
            [
                str(BASE_PATH.joinpath(dut).absolute())
                for dut in manifest_vars["general"]["sources_under_test"]
            ]
            + [str(MANIFEST_PATH.parent.joinpath(f"{proof}.c").absolute())],
            variables={"cflags": manifest_vars["general"]["cflags"]},
        )
        writer.build(
            f"{proof}.instrumented.goto",
            "instrument",
            f"{proof}.goto",
            variables={
                "apply_loop_contracts": "--apply-loop-contracts"
                if manifest_vars["general"]["apply_loop_contracts"]
                else "",
                "enforce_contracts": " ".join(
                    [
                        f"--enforce-contract {func}"
                        for func in manifest_vars["proofs"][proof]["enforce"]
                    ]
                ),
                "replace_calls_with_contracts": " ".join(
                    [
                        f"--replace-call-with-contract {func}"
                        for func in manifest_vars["proofs"][proof]["replace"]
                    ]
                ),
            },
        )
        writer.build(
            f"{proof}.result.txt",
            "prove",
            f"{proof}.instrumented.goto",
            variables={"object_bits": manifest_vars["proofs"][proof]["object_bits"]},
        )

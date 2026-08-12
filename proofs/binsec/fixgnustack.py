import sys

import lief.ELF

binary = lief.ELF.parse(sys.argv[1], lief.ELF.ParserConfig())

assert binary is not None

for segment in binary.segments:
    if segment.type == lief.ELF.Segment.TYPE.GNU_STACK:
        segment.virtual_size = 0

binary.write(sys.argv[1] + ".patched")

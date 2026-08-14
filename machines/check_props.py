import pathlib
import sys

import tomllib

MANIFEST_PATH = pathlib.Path(sys.argv[1])

with open(MANIFEST_PATH, "rb") as manifest_file:
    manifest = tomllib.load(manifest_file)

for req in sys.argv[2:]:
    if req == "supports-tests":
        print("true" if manifest["testing"]["enabled"] else "false")
    elif req == "supports-binsec":
        print("true" if manifest["binsec"]["enabled"] else "false")
    elif req == "tests-disabled-why":
        print(manifest["testing"]["disabled_reason"])
    elif req == "binsec-disabled-why":
        print(manifest["binsec"]["disabled_reason"])

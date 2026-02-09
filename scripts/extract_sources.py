#!/usr/bin/env python3
"""Extract BoringSSL C++ source files from gen/sources.json.

Prints bcm + crypto target .cc files prefixed with third_party/boringssl/,
ready to paste into the .cabal file's cxx-sources section.
"""

import json
import sys
from pathlib import Path

BORINGSSL_DIR = Path(__file__).resolve().parent.parent / "third_party" / "boringssl"
SOURCES_JSON = BORINGSSL_DIR / "gen" / "sources.json"

def main():
    with open(SOURCES_JSON) as f:
        sources = json.load(f)

    files = []
    # bcm target (unity build - just bcm.cc)
    for src in sources["bcm"]["srcs"]:
        files.append(f"third_party/boringssl/{src}")
    # crypto target
    for src in sources["crypto"]["srcs"]:
        files.append(f"third_party/boringssl/{src}")

    for f in sorted(files):
        print(f"    {f}")

if __name__ == "__main__":
    main()

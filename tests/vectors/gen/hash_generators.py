#!/usr/bin/env python3
"""Pin every KAT generator source file by SHA-256, per the provenance requirement.

Run:  python tests/vectors/gen/hash_generators.py  ->  gen/HASHES.txt
"""
import hashlib
import os

HERE = os.path.dirname(__file__)
FILES = [
    "derive_groups.py",
    "srp_track2_kat.py",
    "jpake_kat.py",
    "dragonfly_kat.py",
    "hash_generators.py",
]


def main() -> None:
    lines = []
    for name in FILES:
        path = os.path.join(HERE, name)
        with open(path, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        lines.append(f"{digest}  {name}")
    out = os.path.join(HERE, "HASHES.txt")
    with open(out, "w", encoding="utf-8") as f:
        f.write("# SHA-256 of PAKE Gate KAT generator sources (pinned per provenance).\n")
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()

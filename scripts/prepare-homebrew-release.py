#!/usr/bin/env python3
"""Update the formula from a published tag; never publish or submit anything."""
import argparse
import hashlib
import io
import pathlib
import re
import tarfile
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag", help="Published stable tag, e.g. v0.3.1")
    parser.add_argument("--license", required=True, choices=["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause"],
                        help="SPDX identifier of the license already adopted in the release")
    args = parser.parse_args()
    if not re.fullmatch(r"v\d+\.\d+\.\d+", args.tag):
        parser.error("expected a stable vMAJOR.MINOR.PATCH tag")
    url = f"https://github.com/koehn/mop/archive/refs/tags/{args.tag}.tar.gz"
    with urllib.request.urlopen(url, timeout=60) as response:
        archive = response.read()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as source:
        members = source.getmembers()
        root = members[0].name.split("/")[0]

        def read(name):
            member = source.getmember(f"{root}/{name}")
            if not member.isfile():
                raise ValueError(f"{name} must be a regular file")
            return source.extractfile(member).read().decode("utf-8")

        if not read("LICENSE").strip():
            raise ValueError("the tagged release must contain a nonempty LICENSE")
        version = args.tag[1:]
        if not re.search(r'version:\s*"' + re.escape(version) + r'"', read("Sources/MopCLI/Mop.swift")):
            raise ValueError("tag and CLI version do not match")
        read("Package.resolved")
    formula = pathlib.Path(__file__).resolve().parents[1] / "Formula/mop.rb"
    current = formula.read_text()
    metadata = (f'  url "{url}"\n'
                f'  sha256 "{hashlib.sha256(archive).hexdigest()}"\n'
                f'  license "{args.license}"\n')
    updated, count = re.subn(r'  url .*?\n(?=  head )', lambda _: metadata, current, count=1, flags=re.S)
    if count != 1:
        raise ValueError("could not locate formula metadata; no changes made")
    formula.write_text(updated)
    print(f"Updated {formula} for {args.tag}. Review the license, diff, and brew audit before publishing.")


if __name__ == "__main__":
    main()

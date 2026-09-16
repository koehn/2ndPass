#!/usr/bin/env python3
"""Offline tests for release metadata updates and failure-before-write behavior."""
import importlib.util
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("prepare", ROOT / "scripts/prepare-homebrew-release.py")
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class ReleaseTests(unittest.TestCase):
    def run_prepare(self, *, version="0.3.1", license_file=True):
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w:gz") as source:
            files = {"Sources/MopCLI/Mop.swift": f'version: "{version}"', "Package.resolved": "{}"}
            if license_file:
                files["LICENSE"] = "Test license fixture"
            for name, contents in files.items():
                data = contents.encode()
                member = tarfile.TarInfo("mop-0.3.1/" + name)
                member.size = len(data)
                source.addfile(member, io.BytesIO(data))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Formula").mkdir()
            formula = root / "Formula/mop.rb"
            original = (ROOT / "Formula/mop.rb").read_text()
            formula.write_text(original)
            with patch.object(prepare, "__file__", str(root / "scripts/prepare-homebrew-release.py")), \
                 patch.object(sys, "argv", ["prepare", "v0.3.1", "--license", "MIT"]), \
                 patch.object(prepare.urllib.request, "urlopen", return_value=io.BytesIO(archive.getvalue())):
                if version != "0.3.1" or not license_file:
                    with self.assertRaises((ValueError, KeyError)):
                        prepare.main()
                    self.assertEqual(original, formula.read_text())
                else:
                    prepare.main()
                    updated = formula.read_text()
                    self.assertIn('/archive/refs/tags/v0.3.1.tar.gz"', updated)
                    self.assertIn('  license "MIT"', updated)
                    self.assertNotIn('  version "0.3.0"', updated)
                    self.assertIn(prepare.hashlib.sha256(archive.getvalue()).hexdigest(), updated)
                    self.assertEqual(original.split("  head ", 1)[1], updated.split("  head ", 1)[1])

    def test_release_metadata(self):
        self.run_prepare()

    def test_version_mismatch_leaves_formula_intact(self):
        self.run_prepare(version="0.3.0")

    def test_missing_license_leaves_formula_intact(self):
        self.run_prepare(license_file=False)


if __name__ == "__main__":
    unittest.main()

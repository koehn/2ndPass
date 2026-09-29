"""Deployment accepts published measurements without exposing arbitrary logs."""
from pathlib import Path
import tempfile
import unittest

from deploy import PUBLIC_PROFILING, validate_output


class PublicOutputTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name)
        (self.output / 'index.html').write_text('<html></html>')

    def write(self, name):
        path = self.output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{}\n')
        return path

    def test_published_measurements_are_allowed(self):
        for name in PUBLIC_PROFILING:
            self.write(name)
        validate_output(self.output)

    def test_unreviewed_logs_and_wrong_locations_are_rejected(self):
        for name in ('profiling/private.jsonl', 'profiling/v7-private.jsonl',
                     'v7-cloud-2026-09-27.jsonl', 'credentials.json'):
            with self.subTest(name=name):
                path = self.write(name)
                with self.assertRaisesRegex(ValueError, 'Unexpected public output'):
                    validate_output(self.output)
                path.unlink()

    def test_allowlisted_name_cannot_be_a_symlink(self):
        path = self.output / sorted(PUBLIC_PROFILING)[0]
        path.parent.mkdir()
        path.symlink_to(self.output / 'index.html')
        with self.assertRaisesRegex(ValueError, 'Unexpected public output'):
            validate_output(self.output)


if __name__ == '__main__':
    unittest.main()

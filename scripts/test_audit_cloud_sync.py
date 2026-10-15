#!/usr/bin/env python3
"""Offline regression checks for exported CloudSync diagnostics."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("audit", Path(__file__).with_name("audit-cloud-sync.py"))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class AuditTimingTests(unittest.TestCase):
    def test_timings_ignore_invalid_samples_and_retain_counts(self):
        lines = [
            f"Access trace: rotation batch fetch op=- item=- generation=- recipient=- record=- elapsedMs={value}"
            for value in ("10", "20.5", "nan", "inf", "-1", "broken")
        ]
        row = audit.summarize(lines)["stages"]["rotation batch fetch"]
        self.assertEqual(row["events"], 6)
        self.assertEqual(row["timingMs"],
                         {"samples": 2, "total": 30.5, "p50": 10, "p95": 20.5, "max": 20.5})

    def test_old_logs_and_duplicate_grants_still_work(self):
        lines = [
            f"Access trace: content submitted op=o item=i generation=g recipient=r record={record} "
            "kind=MopContentGrantV3 payloadBytes=744"
            for record in ("a", "a", "b")
        ]
        result = audit.summarize(lines)
        row = result["stages"]["content submitted"]
        self.assertEqual(row["payloadBytes"], 2232)
        self.assertEqual(row["distinctRecordAddresses"], 2)
        self.assertNotIn("timingMs", row)
        self.assertEqual(result["additionalGrantAddressesForSameAccess"], 1)


if __name__ == "__main__":
    unittest.main()

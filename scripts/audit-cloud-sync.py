#!/usr/bin/env python3
"""Read exported CloudSync logs; never contact CloudKit or open app data.
Usage: python3 scripts/audit-cloud-sync.py mac:rotation:/tmp/mac-rotation.log ...
Each input must contain one non-overlapping device/phase capture. Output counts
logical events/payload bytes, NOT CloudKit requests, wire bytes, or billing.
"""
import collections
import json
import math
import re
import sys

EVENT = re.compile(r"Access trace: (.*?) op=(\S+) item=(\S+) generation=(\S+) recipient=(\S+) record=(\S+)\s*(.*)")


def summarize(lines):
    stages = collections.defaultdict(lambda: {"events": 0, "payloadBytes": 0, "systemFieldBytes": 0, "records": set(), "elapsed": []})
    grants = collections.defaultdict(set)
    for line in lines:
        match = EVENT.search(line)
        if not match:
            continue
        stage, op, item, generation, recipient, record, detail = match.groups()
        fields = dict(re.findall(r"(\w+)=([^\s]+)", detail))
        row = stages[stage]
        row["events"] += 1
        for key in ("payloadBytes", "systemFieldBytes"):
            value = fields.get(key, "0")
            if value.isdecimal():
                row[key] += int(value)
        try:
            elapsed = float(fields.get("elapsedMs", "nan"))
            if math.isfinite(elapsed) and elapsed >= 0:
                row["elapsed"].append(elapsed)
        except ValueError:
            pass
        if record != "-":
            row["records"].add(record)
        if stage == "content submitted" and fields.get("kind") == "MopContentGrantV3":
            grants[(item, generation, recipient)].add(record)
    result = {}
    for stage, row in sorted(stages.items()):
        records = row.pop("records")
        elapsed = sorted(row.pop("elapsed"))
        if elapsed:
            row["timingMs"] = {
                "samples": len(elapsed),
                "total": sum(elapsed),
                "p50": elapsed[math.ceil(len(elapsed) * .50) - 1],
                "p95": elapsed[math.ceil(len(elapsed) * .95) - 1],
                "max": elapsed[-1],
            }
        row["distinctRecordAddresses"] = len(records)
        result[stage] = row
    return {"stages": result, "additionalGrantAddressesForSameAccess": sum(max(0, len(v) - 1) for v in grants.values())}


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    results = {}
    for argument in sys.argv[1:]:
        device, phase, path = argument.split(":", 2)
        key = device + ":" + phase
        if key in results:
            raise SystemExit("Duplicate device/phase; merge captures without overlapping log intervals first")
        with open(path, encoding="utf-8") as stream:
            results[key] = summarize(stream)
    print(json.dumps(results, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

```python
"""
029_alarm_handlers.py — Network Alarm Correlation and Suppression Engine

Purpose:
    Reads a stream of network alarm events (JSON, one object per line) and
    applies correlation rules to reduce alert fatigue:
      - Root-cause collapse: N alarms on the same device within a time window
        are folded into one parent alarm.
      - Maintenance suppression: alarms for devices listed in a suppression
        file are silently dropped.
      - Flap filter: alarm/clear pairs that resolve within a hold-down period
        are discarded as transient.

Usage:
    # Process a log of alarm events and print correlated output
    python 029_alarm_handlers.py --input alarms.jsonl --window 60 --hold-down 30

    # Suppress alarms for devices under maintenance
    python 029_alarm_handlers.py --input alarms.jsonl --suppress maintenance.txt

    # Write correlated alarms to a file instead of stdout
    python 029_alarm_handlers.py --input alarms.jsonl --output correlated.jsonl

Prerequisites:
    Python 3.8+, stdlib only.

Input format (one JSON object per line):
    {"timestamp": "2024-01-15T10:00:00", "device": "router1", "alarm_type":
     "LINK_DOWN", "severity": "CRITICAL", "interface": "GigE0/0", "state": "RAISE"}

    "state" must be "RAISE" or "CLEAR".
"""

import argparse
import json
import logging
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

LOG = logging.getLogger(__name__)

SEVERITY_RANK = {"CRITICAL": 4, "MAJOR": 3, "MINOR": 2, "WARNING": 1}


def load_suppression_list(path: str) -> set:
    devices = set()
    try:
        for line in Path(path).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                devices.add(line)
        LOG.info("Loaded %d suppressed devices from %s", len(devices), path)
    except OSError as exc:
        LOG.error("Cannot read suppression file: %s", exc)
    return devices


def parse_timestamp(ts: str) -> datetime:
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    raise ValueError(f"Unrecognised timestamp format: {ts!r}")


def correlate(events: list[dict], window_s: int, hold_down_s: int) -> list[dict]:
    """
    Two-pass correlation:
      Pass 1 — flap filter: drop RAISE events whose matching CLEAR arrives
               within hold_down_s seconds.
      Pass 2 — root-cause collapse: group surviving RAISE events by device
               within window_s seconds; emit one parent per group with the
               worst severity and a child list.
    """
    # --- Pass 1: flap filter ---
    raise_index: dict[str, dict] = {}  # key → event
    surviving = []

    def _key(ev: dict) -> str:
        return f"{ev['device']}|{ev['alarm_type']}|{ev.get('interface', '')}"

    for ev in events:
        k = _key(ev)
        if ev["state"] == "RAISE":
            raise_index[k] = ev
        elif ev["state"] == "CLEAR":
            origin = raise_index.pop(k, None)
            if origin is None:
                continue
            delta = (ev["_ts"] - origin["_ts"]).total_seconds()
            if delta <= hold_down_s:
                LOG.debug("Flap suppressed: %s cleared in %.0fs", k, delta)
            else:
                surviving.append(origin)
                surviving.append(ev)

    surviving.extend(raise_index.values())

    # --- Pass 2: root-cause collapse ---
    surviving.sort(key=lambda e: e["_ts"])
    buckets: dict[str, list] = defaultdict(list)
    bucket_open: dict[str, datetime] = {}

    correlated: list[dict] = []

    for ev in surviving:
        if ev["state"] != "RAISE":
            correlated.append(ev)
            continue
        dev = ev["device"]
        now = ev["_ts"]
        if dev in bucket_open and (now - bucket_open[dev]).total_seconds() <= window_s:
            buckets[dev].append(ev)
        else:
            if dev in buckets and buckets[dev]:
                correlated.append(_collapse(dev, buckets[dev]))
            buckets[dev] = [ev]
            bucket_open[dev] = now

    for dev, group in buckets.items():
        if group:
            correlated.append(_collapse(dev, group))

    return correlated


def _collapse(device: str, group: list[dict]) -> dict:
    if len(group) == 1:
        return group[0]
    worst = max(group, key=lambda e: SEVERITY_RANK.get(e.get("severity", ""), 0))
    return {
        "timestamp": worst["timestamp"],
        "device": device,
        "alarm_type": "ROOT_CAUSE_COLLAPSE",
        "severity": worst["severity"],
        "state": "RAISE",
        "child_count": len(group),
        "children": [
            {"alarm_type": e["alarm_type"], "interface": e.get("interface", "")}
            for e in group
        ],
        "_ts": worst["_ts"],
    }


def _strip_internal(ev: dict) -> dict:
    return {k: v for k, v in ev.items() if not k.startswith("_")}


def main():
    parser = argparse.ArgumentParser(
        description="Correlate and suppress network alarm events."
    )
    parser.add_argument("--input", default="-", help="JSONL alarm file (- = stdin)")
    parser.add_argument("--output", default="-", help="JSONL output file (- = stdout)")
    parser.add_argument("--suppress", metavar="FILE", help="Device suppression list")
    parser.add_argument(
        "--window",
        type=int,
        default=60,
        metavar="SECONDS",
        help="Root-cause correlation window (default: 60s)",
    )
    parser.add_argument(
        "--hold-down",
        type=int,
        default=30,
        metavar="SECONDS",
        help="Flap filter hold-down period (default: 30s)",
    )
    parser.add_argument(
        "--log-level",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    suppressed = load_suppression_list(args.suppress) if args.suppress else set()

    in_fh = sys.stdin if args.input == "-" else open(args.input)
    out_fh = sys.stdout if args.output == "-" else open(args.output, "w")

    raw_events: list[dict] = []
    for lineno, line in enumerate(in_fh, 1):
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
            ev["_ts"] = parse_timestamp(ev["timestamp"])
        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            LOG.warning("Line %d skipped (%s): %s", lineno, exc, line[:80])
            continue

        if ev.get("device") in suppressed:
            LOG.debug("Suppressed device %s", ev["device"])
            continue

        raw_events.append(ev)

    if in_fh is not sys.stdin:
        in_fh.close()

    LOG.info("Loaded %d events after suppression", len(raw_events))

    results = correlate(raw_events, args.window, args.hold_down)

    written = 0
    for ev in results:
        out_fh.write(json.dumps(_strip_internal(ev)) + "\n")
        written += 1

    if out_fh is not sys.stdout:
        out_fh.close()

    LOG.info("Wrote %d correlated alarms", written)
    print(
        f"Input: {len(raw_events)} events  →  Output: {written} alarms "
        f"(window={args.window}s, hold-down={args.hold_down}s)",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
```
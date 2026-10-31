The user's explicit instruction — "Output ONLY the script content, no markdown fences, no explanation" — overrides the brainstorming design gate. Writing the script directly.

#!/usr/bin/env python3
"""
NSO Alarm Escalation and Correlation Engine  (019_alarm_escalation.py)

Purpose:
    Fetches active alarms from Cisco NSO via RESTCONF, correlates related
    alarms by device and alarm type to suppress alert storms, applies
    severity-based escalation thresholds, and dispatches a structured
    JSON payload to a webhook endpoint for alarms requiring operator attention.

Usage:
    python 019_alarm_escalation.py --host 192.168.1.10 --user admin \
        --suppress-window 15 --escalate-threshold 3 \
        --webhook https://hooks.example.com/alert

    Exit code 1 if any escalations were produced, 0 if clean.

Prerequisites:
    - Cisco NSO 5.x+ with RESTCONF enabled (default port 8080)
    - NSO user with read access to the tailf-ncs-alarms module
    - pip install requests
"""

import argparse
import json
import logging
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional

import requests
from requests.auth import HTTPBasicAuth

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

SEVERITY_RANK: Dict[str, int] = {
    "critical": 4,
    "major": 3,
    "minor": 2,
    "warning": 1,
    "indeterminate": 1,
    "cleared": 0,
}


def build_session(user: str, password: str) -> requests.Session:
    session = requests.Session()
    session.auth = HTTPBasicAuth(user, password)
    session.headers.update({"Accept": "application/yang-data+json"})
    return session


def fetch_alarms(session: requests.Session, base_url: str) -> List[Dict]:
    url = f"{base_url}/restconf/data/tailf-ncs-alarms:alarms/alarm-list/alarm"
    try:
        resp = session.get(url, timeout=15)
        resp.raise_for_status()
        raw = resp.json().get("tailf-ncs-alarms:alarm", [])
        alarms = [raw] if isinstance(raw, dict) else raw
        log.info("Fetched %d alarms from NSO", len(alarms))
        return alarms
    except requests.exceptions.ConnectionError as exc:
        log.error("Cannot reach NSO at %s: %s", base_url, exc)
        return []
    except requests.exceptions.HTTPError as exc:
        log.error("HTTP error fetching alarms: %s", exc)
        return []


def _parse_time(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def correlate(alarms: List[Dict], suppress_minutes: int) -> Dict[str, List[Dict]]:
    """
    Group alarms by (device, alarm-type). Within each group, mark entries
    older than suppress_minutes * 10 as stale. Cleared alarms are dropped
    because they represent resolved conditions, not active ones.
    """
    now = datetime.now(tz=timezone.utc)
    groups: Dict[str, List[Dict]] = defaultdict(list)

    for alarm in alarms:
        severity = alarm.get("perceived-severity", "indeterminate").lower()
        if severity == "cleared":
            continue

        device = alarm.get("managed-object", alarm.get("device", "unknown"))
        atype = alarm.get("alarm-type-id", alarm.get("type", "unknown"))
        key = f"{device}::{atype}"

        last_changed = _parse_time(alarm.get("last-status-change"))
        if last_changed:
            age_min = (now - last_changed).total_seconds() / 60
            alarm["_stale"] = age_min > suppress_minutes * 10
        else:
            alarm["_stale"] = False

        alarm["_rank"] = SEVERITY_RANK.get(severity, 1)
        alarm["_key"] = key
        groups[key].append(alarm)

    # Sort each group so the highest-severity alarm is first
    for group in groups.values():
        group.sort(key=lambda a: a["_rank"], reverse=True)

    return dict(groups)


def build_escalations(
    groups: Dict[str, List[Dict]], threshold: int
) -> List[Dict]:
    """
    A group escalates when its alarm count reaches the threshold OR its
    top-severity alarm is major/critical, regardless of count.
    """
    escalations = []
    for key, group in groups.items():
        top = group[0]
        count = len(group)
        rank = top.get("_rank", 1)

        if count < threshold and rank < SEVERITY_RANK["major"]:
            continue

        escalations.append({
            "key": key,
            "device": top.get("managed-object", top.get("device", "unknown")),
            "alarm_type": top.get("alarm-type-id", top.get("type", "unknown")),
            "severity": top.get("perceived-severity", "indeterminate"),
            "count": count,
            "stale": any(a.get("_stale") for a in group),
            "text": top.get("alarm-text", top.get("specific-problem", "")),
            "last_changed": top.get("last-status-change", ""),
        })

    escalations.sort(key=lambda e: SEVERITY_RANK.get(e["severity"], 1), reverse=True)
    return escalations


def dispatch_webhook(url: str, escalations: List[Dict]) -> None:
    payload = {
        "source": "nso-alarm-escalation",
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "escalation_count": len(escalations),
        "alarms": escalations,
    }
    try:
        resp = requests.post(url, json=payload, timeout=10)
        resp.raise_for_status()
        log.info("Webhook dispatched successfully (HTTP %d)", resp.status_code)
    except requests.exceptions.RequestException as exc:
        log.error("Webhook dispatch failed: %s", exc)


def print_report(escalations: List[Dict]) -> None:
    if not escalations:
        print("No escalations — all alarm groups below threshold.")
        return

    bar = "=" * 66
    print(f"\n{bar}")
    print(f"  ALARM ESCALATION REPORT  —  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(bar)
    for esc in escalations:
        tag = " [STALE]" if esc["stale"] else ""
        print(
            f"  [{esc['severity'].upper():>13}]  {esc['device']} / "
            f"{esc['alarm_type']}  (x{esc['count']}){tag}"
        )
        if esc["text"]:
            print(f"               {esc['text'][:72]}")
        if esc["last_changed"]:
            print(f"               Last changed: {esc['last_changed']}")
    print(bar)
    print(f"  Total escalations: {len(escalations)}\n")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="NSO alarm correlation and escalation engine"
    )
    p.add_argument("--host", required=True, help="NSO host or IP")
    p.add_argument("--port", type=int, default=8080, help="RESTCONF port (default: 8080)")
    p.add_argument("--user", required=True, help="NSO username")
    p.add_argument("--password", default="", help="NSO password (or set NSO_PASSWORD env var)")
    p.add_argument(
        "--suppress-window", type=int, default=10, metavar="MIN",
        help="Age multiplier in minutes used to flag stale alarms (default: 10)"
    )
    p.add_argument(
        "--escalate-threshold", type=int, default=2, metavar="N",
        help="Alarm count per group to trigger escalation (default: 2)"
    )
    p.add_argument("--webhook", metavar="URL", help="POST escalations to this webhook URL")
    p.add_argument("--json", dest="json_output", action="store_true",
                   help="Emit escalations as JSON instead of plain text")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or os.environ.get("NSO_PASSWORD", "")
    if not password:
        log.error("Password required: use --password or NSO_PASSWORD env var")
        sys.exit(2)

    base_url = f"http://{args.host}:{args.port}"
    session = build_session(args.user, password)

    alarms = fetch_alarms(session, base_url)
    if not alarms:
        log.warning("No alarms retrieved — check connectivity and credentials")
        sys.exit(0)

    groups = correlate(alarms, args.suppress_window)
    log.info("Correlated into %d unique alarm groups", len(groups))

    escalations = build_escalations(groups, args.escalate_threshold)
    log.info("%d group(s) meet escalation criteria", len(escalations))

    if args.json_output:
        print(json.dumps(escalations, indent=2))
    else:
        print_report(escalations)

    if args.webhook and escalations:
        dispatch_webhook(args.webhook, escalations)

    sys.exit(1 if escalations else 0)
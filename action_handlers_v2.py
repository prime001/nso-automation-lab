The user's explicit instruction to "Output ONLY the script content" takes precedence over the brainstorming skill. Writing the script directly.

```python
"""
011_change_validator.py — Pre/post change state validator for network maintenance windows.

Captures a device-state snapshot (interface oper-status, BGP neighbors, IPv4 route
count) via NSO RESTCONF before a maintenance window, then compares against live state
after changes are applied.  Generates a pass/fail report to confirm no regressions.

Usage:
    # Save baseline before the change
    python 011_change_validator.py --device router1 --action capture --snapshot /tmp/pre.json

    # Validate live state against the baseline after the change
    python 011_change_validator.py --device router1 --action validate --snapshot /tmp/pre.json

    # Capture a new snapshot AND diff it against the baseline in one step
    python 011_change_validator.py --device router1 --action diff --snapshot /tmp/pre.json

Prerequisites:
    pip install requests
    NSO running with RESTCONF enabled (default http://localhost:8080)
    Device managed in the NSO CDB with live-status tree populated

Environment variables (override CLI defaults):
    NSO_HOST   NSO_PORT   NSO_USER   NSO_PASS
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone

try:
    import requests
    from requests.auth import HTTPBasicAuth
except ImportError:
    sys.exit("requests is required: pip install requests")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

_HOST = os.getenv("NSO_HOST", "localhost")
_PORT = os.getenv("NSO_PORT", "8080")
_BASE = f"http://{_HOST}:{_PORT}/restconf"
_HEADERS = {"Accept": "application/yang-data+json"}


def _get(path: str, auth: HTTPBasicAuth) -> dict:
    resp = requests.get(f"{_BASE}{path}", headers=_HEADERS, auth=auth, timeout=15)
    resp.raise_for_status()
    return resp.json()


def _interfaces(device: str, auth: HTTPBasicAuth) -> dict:
    path = (
        f"/data/tailf-ncs:devices/device={device}"
        "/live-status/ietf-interfaces:interfaces-state/interface"
    )
    try:
        data = _get(path, auth)
        ifaces = data.get("ietf-interfaces:interface", [])
        return {i["name"]: i.get("oper-status", "unknown") for i in ifaces}
    except requests.HTTPError as exc:
        log.warning("Interface fetch failed: %s", exc)
        return {}


def _bgp_neighbors(device: str, auth: HTTPBasicAuth) -> list:
    path = (
        f"/data/tailf-ncs:devices/device={device}"
        "/live-status/Cisco-IOS-XE-bgp-oper:bgp-state-data/neighbors/neighbor"
    )
    try:
        data = _get(path, auth)
        neighbors = data.get("Cisco-IOS-XE-bgp-oper:neighbor", [])
        return [
            n["neighbor-id"]
            for n in neighbors
            if n.get("connection", {}).get("state", "").upper() == "ESTABLISHED"
        ]
    except requests.HTTPError:
        return []


def _route_count(device: str, auth: HTTPBasicAuth) -> int:
    path = (
        f"/data/tailf-ncs:devices/device={device}"
        "/live-status/Cisco-IOS-XE-ip-route-oper:ip-route-data/ipv4-route"
    )
    try:
        data = _get(path, auth)
        return len(data.get("Cisco-IOS-XE-ip-route-oper:ipv4-route", []))
    except requests.HTTPError:
        return -1


def capture(device: str, auth: HTTPBasicAuth) -> dict:
    log.info("Capturing state for device: %s", device)
    ifaces = _interfaces(device, auth)
    bgp = _bgp_neighbors(device, auth)
    routes = _route_count(device, auth)
    log.info(
        "  %d interfaces  |  %d BGP neighbors established  |  %d IPv4 routes",
        len(ifaces), len(bgp), routes,
    )
    return {
        "device": device,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "interfaces": ifaces,
        "bgp_established": bgp,
        "ipv4_route_count": routes,
    }


def compare(before: dict, after: dict) -> list:
    findings = []

    for iface, pre_state in before["interfaces"].items():
        post_state = after["interfaces"].get(iface)
        if post_state is None:
            findings.append(("WARN", "interface", f"{iface}: absent after change"))
        elif pre_state == "up" and post_state != "up":
            findings.append(("FAIL", "interface", f"{iface}: was up, now {post_state}"))

    for iface in after["interfaces"]:
        if iface not in before["interfaces"]:
            findings.append(("INFO", "interface", f"{iface}: new interface detected"))

    pre_bgp = set(before["bgp_established"])
    post_bgp = set(after["bgp_established"])
    for addr in pre_bgp - post_bgp:
        findings.append(("FAIL", "bgp", f"neighbor {addr} no longer established"))
    for addr in post_bgp - pre_bgp:
        findings.append(("INFO", "bgp", f"neighbor {addr} newly established"))

    pre_r, post_r = before["ipv4_route_count"], after["ipv4_route_count"]
    if pre_r > 0 and post_r >= 0:
        pct = abs(post_r - pre_r) / pre_r * 100
        if pct > 25:
            findings.append(
                ("FAIL", "routes", f"count {pre_r} → {post_r} ({pct:.1f}% drift)")
            )
        elif pct > 10:
            findings.append(
                ("WARN", "routes", f"count {pre_r} → {post_r} ({pct:.1f}% drift)")
            )

    return findings


def report(before: dict, after: dict, findings: list) -> bool:
    width = 62
    print(f"\n{'=' * width}")
    print(f"  Change Validation — {after['device']}")
    print(f"  PRE  {before['timestamp']}")
    print(f"  POST {after['timestamp']}")
    print(f"{'=' * width}")

    if not findings:
        print("  ALL CHECKS PASSED — no regressions detected\n")
        return True

    for severity, check, detail in findings:
        print(f"  [{severity:<4}] [{check.upper():<9}] {detail}")

    fails = sum(1 for s, _, __ in findings if s == "FAIL")
    warns = sum(1 for s, _, __ in findings if s == "WARN")
    infos = sum(1 for s, _, __ in findings if s == "INFO")
    print(f"\n  {fails} FAIL  {warns} WARN  {infos} INFO\n")
    return fails == 0


def main():
    parser = argparse.ArgumentParser(
        description="Pre/post change state validator via NSO RESTCONF",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--device", required=True, help="NSO device name")
    parser.add_argument(
        "--action",
        choices=["capture", "validate", "diff"],
        required=True,
        help="capture: save baseline; validate: check live vs baseline; "
             "diff: capture post-snapshot and compare",
    )
    parser.add_argument("--snapshot", required=True, help="Baseline snapshot JSON path")
    parser.add_argument("--user", default=os.getenv("NSO_USER", "admin"))
    parser.add_argument("--password", default=os.getenv("NSO_PASS", "admin"))
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    auth = HTTPBasicAuth(args.user, args.password)

    if args.action == "capture":
        snap = capture(args.device, auth)
        with open(args.snapshot, "w") as fh:
            json.dump(snap, fh, indent=2)
        log.info("Baseline saved to %s", args.snapshot)

    else:
        if not os.path.exists(args.snapshot):
            sys.exit(f"Snapshot not found: {args.snapshot}")
        with open(args.snapshot) as fh:
            before = json.load(fh)
        after = capture(args.device, auth)

        if args.action == "diff":
            post_path = args.snapshot.replace(".json", "_post.json")
            with open(post_path, "w") as fh:
                json.dump(after, fh, indent=2)
            log.info("Post-change snapshot saved to %s", post_path)

        findings = compare(before, after)
        passed = report(before, after, findings)
        sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
```
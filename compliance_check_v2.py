The user's request is fully specified — all design decisions are made, the constraints are explicit, and the output format is "script only." The brainstorming skill is designed for open-ended idea refinement, not for executing a complete, well-defined spec. User instructions take priority per the skill's own guidance.

Writing the BGP neighbor compliance script (next in sequence, not duplicating existing compliance_check or config_audit):

```python
"""
013_bgp_neighbor_compliance.py - BGP Neighbor State Compliance Checker

Purpose:
    Validates BGP neighbor sessions against an expected topology baseline.
    Connects to network devices via SSH, collects BGP summary output, and
    checks each peer's establishment state against a JSON-defined golden config.
    Exits non-zero when any device or peer is out of compliance.

Usage:
    # Single device
    python 013_bgp_neighbor_compliance.py \\
        --device 192.0.2.1 --platform ios-xe \\
        --username admin --password-env NET_PASS \\
        --baseline baseline.json

    # Fleet via inventory file
    python 013_bgp_neighbor_compliance.py \\
        --inventory inventory.json \\
        --username admin --password-env NET_PASS \\
        --baseline baseline.json --output report.json --verbose

Prerequisites:
    pip install paramiko

    inventory.json  — list of {"host": "...", "platform": "ios-xe|ios-xr|nxos"}
    baseline.json   — {"<host>": {"neighbors": [{"ip": "...", "state": "Established"}]}}

Exit codes:
    0  all devices compliant
    1  configuration/connectivity error
    2  one or more compliance failures
"""

import argparse
import json
import logging
import os
import re
import sys
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional

import paramiko

LOG = logging.getLogger(__name__)


@dataclass
class PeerResult:
    peer_ip: str
    expected_state: str
    actual_state: str
    compliant: bool
    detail: str = ""


@dataclass
class DeviceResult:
    host: str
    reachable: bool
    peers: List[dict]
    compliant: bool
    error: Optional[str] = None


def _ssh_run(client: paramiko.SSHClient, command: str, timeout: int = 15) -> str:
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode(errors="replace").strip()
    err = stderr.read().decode(errors="replace").strip()
    if err:
        LOG.debug("device stderr: %s", err)
    return out


def _connect(host: str, username: str, password: str, port: int) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=10,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def _parse_ios(output: str) -> Dict[str, str]:
    """Parse IOS-XE / NX-OS 'show bgp summary': prefix count when up, text state when down."""
    peers: Dict[str, str] = {}
    pattern = re.compile(
        r"^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\S+)",
        re.MULTILINE,
    )
    for m in pattern.finditer(output):
        ip, state_or_count = m.group(1), m.group(2)
        peers[ip] = "Established" if state_or_count.isdigit() else state_or_count
    return peers


def _parse_xr(output: str) -> Dict[str, str]:
    """Parse IOS-XR 'show bgp summary': state is the last column."""
    peers: Dict[str, str] = {}
    pattern = re.compile(
        r"^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\w+)",
        re.MULTILINE,
    )
    for m in pattern.finditer(output):
        peers[m.group(1)] = m.group(2)
    return peers


_PARSERS = {"ios-xe": _parse_ios, "nxos": _parse_ios, "ios-xr": _parse_xr}


def check_device(
    host: str,
    platform: str,
    username: str,
    password: str,
    baseline: dict,
    port: int,
) -> DeviceResult:
    expected_peers = baseline.get(host, {}).get("neighbors", [])
    if not expected_peers:
        LOG.warning("%s: no baseline entries — skipping", host)
        return DeviceResult(host=host, reachable=True, peers=[], compliant=True)

    try:
        client = _connect(host, username, password, port)
    except Exception as exc:
        LOG.error("%s: connection failed: %s", host, exc)
        return DeviceResult(host=host, reachable=False, peers=[], compliant=False, error=str(exc))

    try:
        raw = _ssh_run(client, "show bgp summary")
        parse = _PARSERS.get(platform, _parse_ios)
        actual = parse(raw)
    except Exception as exc:
        LOG.error("%s: command failed: %s", host, exc)
        return DeviceResult(host=host, reachable=True, peers=[], compliant=False, error=str(exc))
    finally:
        client.close()

    results: List[PeerResult] = []
    for entry in expected_peers:
        ip = entry["ip"]
        want = entry.get("state", "Established")
        got = actual.get(ip, "NOT_FOUND")
        ok = got == want
        results.append(PeerResult(ip, want, got, ok, "" if ok else f"want={want} got={got}"))

    return DeviceResult(
        host=host,
        reachable=True,
        peers=[asdict(r) for r in results],
        compliant=all(r.compliant for r in results),
    )


def _build_inventory(args) -> List[dict]:
    if args.inventory:
        with open(args.inventory) as f:
            return json.load(f)
    return [{"host": args.device, "platform": args.platform}]


def main() -> int:
    p = argparse.ArgumentParser(description="BGP neighbor state compliance checker")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--device", help="Single device hostname or IP")
    src.add_argument("--inventory", help="JSON inventory file (list of host/platform objects)")
    p.add_argument("--platform", default="ios-xe", choices=list(_PARSERS),
                   help="Platform when using --device (default: ios-xe)")
    p.add_argument("--username", required=True, help="SSH username")
    p.add_argument("--password", help="SSH password (prefer --password-env)")
    p.add_argument("--password-env", default="NET_PASS",
                   help="Env var holding the SSH password (default: NET_PASS)")
    p.add_argument("--baseline", required=True, help="JSON baseline file")
    p.add_argument("--output", help="Write JSON compliance report to this file")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(message)s",
    )

    password = args.password or os.environ.get(args.password_env)
    if not password:
        LOG.error("No password — use --password or set %s", args.password_env)
        return 1

    with open(args.baseline) as f:
        baseline = json.load(f)

    inventory = _build_inventory(args)
    all_results = []

    for device in inventory:
        host, platform = device["host"], device.get("platform", "ios-xe")
        LOG.info("Checking %s (%s)", host, platform)
        result = check_device(host, platform, args.username, password, baseline, args.port)
        all_results.append(asdict(result))
        label = "PASS" if result.compliant else "FAIL"
        LOG.info("%s %s — %d peer(s) evaluated", label, host, len(result.peers))
        for peer in result.peers:
            indicator = "  OK  " if peer["compliant"] else "  FAIL"
            LOG.info("%s peer=%-15s expected=%-14s actual=%s",
                     indicator, peer["peer_ip"], peer["expected_state"], peer["actual_state"])

    failed = sum(1 for r in all_results if not r["compliant"])
    LOG.info("Summary: %d/%d devices compliant", len(all_results) - failed, len(all_results))

    report = {
        "devices": all_results,
        "summary": {"total": len(all_results), "compliant": len(all_results) - failed, "failed": failed},
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        LOG.info("Report written to %s", args.output)
    else:
        print(json.dumps(report, indent=2))

    return 0 if failed == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
```
The repo is at `/opt/NetAutoCommitter`. The user wants the script output only (no markdown fences, no explanation). Let me write it.

```python
#!/usr/bin/env python3
"""
015_yang_capabilities.py — NSO YANG Module Capability Diff

Queries Cisco NSO's RESTCONF interface to retrieve the YANG module capabilities
advertised by each managed device, then computes a cross-device capability matrix.
Use this before deploying a new service template to verify every target device
supports the required YANG modules at a compatible revision.

Prerequisites:
    pip install requests
    NSO >= 5.x with RESTCONF enabled (restconf-http-port configured)
    Read-access credentials for the NSO instance

Usage:
    python 015_yang_capabilities.py --nso-host 10.0.0.1 --user admin \
        --devices c-rtr1 c-rtr2 c-rtr3 [--module bgp] [--json]

    # List all devices' common modules and flag version drift:
    python 015_yang_capabilities.py --nso-host 10.0.0.1 --user admin \
        --devices c-rtr1 c-rtr2 --show-common --show-unique --show-drift
"""

import argparse
import getpass
import json
import logging
import sys
from collections import defaultdict
from typing import Optional

import requests
from requests.auth import HTTPBasicAuth

logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


def _session(user: str, password: str, verify: bool) -> requests.Session:
    s = requests.Session()
    s.auth = HTTPBasicAuth(user, password)
    s.headers.update({"Accept": "application/yang-data+json"})
    s.verify = verify
    return s


def fetch_device_capabilities(
    session: requests.Session,
    base_url: str,
    device: str,
    timeout: int,
) -> Optional[dict[str, str]]:
    """Return {module_name: revision} for a single NSO-managed device."""
    url = (
        f"{base_url}/restconf/data/tailf-ncs:devices/device={device}"
        "/capability"
    )
    try:
        resp = session.get(url, timeout=timeout)
        resp.raise_for_status()
    except requests.exceptions.HTTPError as exc:
        log.error("HTTP %s for device %s: %s", exc.response.status_code, device, exc)
        return None
    except requests.exceptions.RequestException as exc:
        log.error("Connection error for device %s: %s", device, exc)
        return None

    data = resp.json()
    caps = data.get("tailf-ncs:capability", [])
    modules: dict[str, str] = {}
    for cap in caps:
        name = cap.get("module")
        revision = cap.get("revision", "")
        if name:
            modules[name] = revision
    log.info("Device %-20s  %d modules", device, len(modules))
    return modules


def diff_capabilities(
    device_caps: dict[str, dict[str, str]],
) -> tuple[set[str], dict[str, list[str]], dict[str, dict[str, list[str]]]]:
    """
    Returns:
        common  — modules present on ALL devices
        unique  — {device: [module, ...]} modules only on that device
        drift   — {module: {revision: [device, ...]}} version mismatches
    """
    all_modules: dict[str, dict[str, str]] = defaultdict(dict)  # module -> {device: rev}
    for device, caps in device_caps.items():
        for mod, rev in caps.items():
            all_modules[mod][device] = rev

    devices = set(device_caps.keys())
    common = {m for m, d in all_modules.items() if set(d.keys()) == devices}

    unique: dict[str, list[str]] = defaultdict(list)
    for mod, d in all_modules.items():
        if len(d) == 1:
            only_device = next(iter(d))
            unique[only_device].append(mod)

    drift: dict[str, dict[str, list[str]]] = {}
    for mod in common:
        rev_map: dict[str, list[str]] = defaultdict(list)
        for device, rev in all_modules[mod].items():
            rev_map[rev].append(device)
        if len(rev_map) > 1:
            drift[mod] = dict(rev_map)

    return common, dict(unique), drift


def print_report(
    device_caps: dict[str, dict[str, str]],
    module_filter: Optional[str],
    show_common: bool,
    show_unique: bool,
    show_drift: bool,
    as_json: bool,
) -> None:
    common, unique, drift = diff_capabilities(device_caps)

    if module_filter:
        matched = {
            device: caps.get(module_filter)
            for device, caps in device_caps.items()
        }
        if as_json:
            print(json.dumps(matched, indent=2))
        else:
            print(f"\nModule: {module_filter}")
            for device, rev in matched.items():
                status = rev if rev is not None else "NOT PRESENT"
                print(f"  {device:<24} {status}")
        return

    report: dict = {}
    if show_common:
        report["common_count"] = len(common)
        report["common"] = sorted(common)
    if show_unique:
        report["unique"] = {d: sorted(mods) for d, mods in unique.items()}
    if show_drift:
        report["revision_drift"] = drift

    if as_json:
        print(json.dumps(report, indent=2))
        return

    if show_common:
        print(f"\n=== Common modules ({len(common)}) ===")
        for m in sorted(common):
            print(f"  {m}")
    if show_unique:
        print("\n=== Unique modules per device ===")
        for device, mods in sorted(unique.items()):
            print(f"  {device}:")
            for m in sorted(mods):
                print(f"    {m}")
    if show_drift:
        if drift:
            print(f"\n=== Revision drift ({len(drift)} module(s)) ===")
            for mod, rev_map in sorted(drift.items()):
                print(f"  {mod}")
                for rev, devs in sorted(rev_map.items()):
                    print(f"    {rev or '(none)':30}  {', '.join(sorted(devs))}")
        else:
            print("\n=== No revision drift detected ===")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare YANG module capabilities across NSO-managed devices"
    )
    parser.add_argument("--nso-host", required=True, help="NSO hostname or IP")
    parser.add_argument("--port", type=int, default=8080, help="RESTCONF port (default: 8080)")
    parser.add_argument("--user", required=True, help="NSO username")
    parser.add_argument("--password", help="NSO password (prompted if omitted)")
    parser.add_argument("--devices", nargs="+", required=True, help="Device names in NSO")
    parser.add_argument("--module", help="Look up a specific module across all devices")
    parser.add_argument("--show-common", action="store_true", help="Print modules on all devices")
    parser.add_argument("--show-unique", action="store_true", help="Print per-device unique modules")
    parser.add_argument("--show-drift", action="store_true", help="Print revision mismatches")
    parser.add_argument("--no-verify", action="store_true", help="Disable TLS certificate check")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout seconds")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Output JSON")
    args = parser.parse_args()

    if not (args.module or args.show_common or args.show_unique or args.show_drift):
        parser.error("Specify at least one of --module, --show-common, --show-unique, --show-drift")

    password = args.password or getpass.getpass(f"Password for {args.user}@{args.nso_host}: ")
    base_url = f"https://{args.nso_host}:{args.port}"
    session = _session(args.user, password, verify=not args.no_verify)

    device_caps: dict[str, dict[str, str]] = {}
    for device in args.devices:
        caps = fetch_device_capabilities(session, base_url, device, args.timeout)
        if caps is not None:
            device_caps[device] = caps

    if not device_caps:
        log.error("No capability data retrieved; check connectivity and credentials")
        return 1

    if len(device_caps) < len(args.devices):
        failed = set(args.devices) - set(device_caps)
        log.warning("Skipping failed devices: %s", ", ".join(sorted(failed)))

    print_report(
        device_caps,
        module_filter=args.module,
        show_common=args.show_common,
        show_unique=args.show_unique,
        show_drift=args.show_drift,
        as_json=args.as_json,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
```
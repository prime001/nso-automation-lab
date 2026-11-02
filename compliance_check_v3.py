The repo referenced (`nso-automation-lab`) isn't local — this is a portfolio script request, so I'll output the script directly as requested.

```python
"""
NSO Interface Description Compliance Checker

Purpose:
    Validates that all physical interfaces on NSO-managed devices have
    non-empty descriptions matching a configurable naming pattern.
    Uses the NSO RESTCONF API — no direct device SSH required.

    Exits 0 if every checked device is compliant, 2 if any violations
    exist, 1 on fatal error (unreachable NSO, auth failure, etc.).

Usage:
    python 023_interface_desc_compliance.py \
        --nso-host 192.168.1.10 --user admin --password secret \
        --pattern "^[A-Z]{2,4}-[A-Za-z0-9._-]+" \
        --devices dist-sw-01 dist-sw-02

Prerequisites:
    - Cisco NSO 5.x+ with RESTCONF enabled (default port 8080)
    - NSO account with read access to device CDB
    - Devices onboarded and sync-from-network completed
    - pip install requests
"""

import argparse
import json
import logging
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import requests
from requests.auth import HTTPBasicAuth

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

ACCEPT_JSON = {"Accept": "application/yang-data+json"}

INTERFACE_YANG_PATHS = [
    "Cisco-IOS-XE-native:native/interface",
    "tailf-ned-cisco-ios:interface",
    "Cisco-IOS-XR-ifmgr-cfg:interface-configurations/interface-configuration",
]

PHYSICAL_TYPES = {"GigabitEthernet", "TenGigabitEthernet", "HundredGigE",
                  "FortyGigabitEthernet", "FastEthernet", "Ethernet"}


@dataclass
class InterfaceViolation:
    name: str
    reason: str


@dataclass
class DeviceResult:
    device: str
    compliant: bool = False
    violations: List[InterfaceViolation] = field(default_factory=list)
    error: Optional[str] = None


def nso_get(session: requests.Session, url: str) -> Optional[dict]:
    try:
        resp = session.get(url, headers=ACCEPT_JSON, timeout=20)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()
    except requests.Timeout:
        raise RuntimeError(f"Timeout fetching {url}")
    except requests.HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.response.status_code} from {url}")


def list_devices(session: requests.Session, base: str) -> List[str]:
    data = nso_get(session, f"{base}/data/tailf-ncs:devices/device?fields=name")
    if not data:
        return []
    return [d["name"] for d in data.get("tailf-ncs:device", [])]


def fetch_interfaces(session: requests.Session, base: str, device: str) -> Dict[str, Optional[str]]:
    """Return {interface_name: description_or_None} for physical interfaces."""
    interfaces: Dict[str, Optional[str]] = {}

    for yang_path in INTERFACE_YANG_PATHS:
        url = f"{base}/data/tailf-ncs:devices/device={device}/config/{yang_path}"
        try:
            data = nso_get(session, url)
        except RuntimeError:
            continue
        if data is None:
            continue

        # Flatten all interface type lists from the response
        for _ns_key, container in data.items():
            if not isinstance(container, dict):
                continue
            for if_type, entries in container.items():
                if if_type not in PHYSICAL_TYPES:
                    continue
                if isinstance(entries, dict):
                    entries = [entries]
                for entry in entries:
                    iface_id = entry.get("name", "")
                    name = f"{if_type}{iface_id}"
                    desc = entry.get("description") or None
                    interfaces[name] = desc
        if interfaces:
            break

    return interfaces


def check_device(
    session: requests.Session,
    base: str,
    device: str,
    pattern: Optional[re.Pattern],
) -> DeviceResult:
    result = DeviceResult(device=device)
    try:
        interfaces = fetch_interfaces(session, base, device)
    except RuntimeError as exc:
        result.error = str(exc)
        log.warning("%s: %s", device, exc)
        return result

    if not interfaces:
        result.error = "No physical interfaces found (device may use unsupported NED)"
        log.warning("%s: %s", device, result.error)
        return result

    for name, desc in interfaces.items():
        if not desc:
            result.violations.append(InterfaceViolation(name=name, reason="missing description"))
        elif pattern and not pattern.search(desc):
            result.violations.append(
                InterfaceViolation(name=name, reason=f"description {desc!r} does not match pattern")
            )

    result.compliant = len(result.violations) == 0
    return result


def render_text(results: List[DeviceResult]) -> None:
    compliant = [r for r in results if r.compliant]
    violations = [r for r in results if not r.compliant and not r.error]
    errors = [r for r in results if r.error]

    print(f"\n{'='*64}")
    print(f"Interface Description Compliance — {len(results)} device(s)")
    print(f"{'='*64}")
    print(f"  Compliant    : {len(compliant)}")
    print(f"  Violations   : {len(violations)}")
    print(f"  Errors       : {len(errors)}")
    print(f"{'='*64}\n")

    for r in violations:
        print(f"FAIL  {r.device}")
        for v in r.violations:
            print(f"        {v.name}: {v.reason}")

    for r in errors:
        print(f"ERROR {r.device}: {r.error}")


def render_json(results: List[DeviceResult]) -> None:
    out = [
        {
            "device": r.device,
            "compliant": r.compliant,
            "violations": [{"interface": v.name, "reason": v.reason} for v in r.violations],
            "error": r.error,
        }
        for r in results
    ]
    print(json.dumps(out, indent=2))


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Check interface description compliance on NSO-managed devices"
    )
    p.add_argument("--nso-host", required=True, help="NSO IP or hostname")
    p.add_argument("--port", type=int, default=8080, help="NSO RESTCONF port (default: 8080)")
    p.add_argument("--user", required=True)
    p.add_argument("--password", required=True)
    p.add_argument(
        "--pattern",
        metavar="REGEX",
        help="Required description pattern (default: any non-empty string)",
    )
    p.add_argument(
        "--devices", nargs="*", metavar="DEV",
        help="Devices to check (default: all NSO-managed devices)",
    )
    p.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format (default: text)",
    )
    p.add_argument("--https", action="store_true", help="Use HTTPS instead of HTTP")
    p.add_argument("--no-verify-ssl", action="store_true", help="Disable TLS certificate validation")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    scheme = "https" if args.https else "http"
    base = f"{scheme}://{args.nso_host}:{args.port}/restconf"

    session = requests.Session()
    session.auth = HTTPBasicAuth(args.user, args.password)
    session.verify = not args.no_verify_ssl

    pattern = re.compile(args.pattern) if args.pattern else None

    try:
        devices = args.devices or list_devices(session, base)
    except RuntimeError as exc:
        log.error("Cannot reach NSO: %s", exc)
        sys.exit(1)

    if not devices:
        log.error("No devices found — check NSO connectivity and onboarding status")
        sys.exit(1)

    log.info("Checking %d device(s)...", len(devices))
    results = [check_device(session, base, dev, pattern) for dev in devices]

    if args.format == "json":
        render_json(results)
    else:
        render_text(results)

    sys.exit(0 if all(r.compliant for r in results) else 2)
```
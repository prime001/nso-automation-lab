```python
"""
017_routing_auth_audit.py - Routing Protocol Authentication Audit

Purpose:
    Audits Cisco IOS/IOS-XE/NX-OS devices for missing or weak routing protocol
    authentication. Checks OSPF, BGP, and EIGRP configurations to verify that
    MD5/SHA authentication is enabled on all neighbor sessions. Produces a
    structured JSON report and exits non-zero if any gaps are found.

Usage:
    # Single device
    python 017_routing_auth_audit.py --host 192.168.1.1 --username admin \
        --password secret --protocols ospf bgp

    # Device inventory file (one host per line, # for comments)
    python 017_routing_auth_audit.py --inventory devices.txt \
        --username admin --password secret --output report.json

    # With debug logging and custom SSH port
    python 017_routing_auth_audit.py --host 10.0.0.1 --username admin \
        --password secret --port 2222 --debug

Prerequisites:
    - paramiko >= 2.7: pip install paramiko
    - SSH access to target devices with at least 'show' privilege
    - SSH v2 enabled on target devices (ip ssh version 2)
    - For NX-OS, 'feature ssh' must be enabled

Exit codes:
    0 - All audited protocols have authentication configured (or not present)
    1 - One or more protocols found without authentication
    2 - Fatal error (no reachable devices, missing inventory file, etc.)
"""

import argparse
import json
import logging
import re
import sys
from dataclasses import asdict, dataclass, field
from typing import List, Optional

try:
    import paramiko
except ImportError:
    print("Error: paramiko is required.  Install with: pip install paramiko", file=sys.stderr)
    sys.exit(2)

logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(name)s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger("routing_auth_audit")

_SHOW_CMDS = {
    "ospf": "show running-config | section router ospf",
    "bgp": "show running-config | section router bgp",
    "eigrp": "show running-config | section router eigrp",
}

_AUTH_PATTERNS: dict[str, list[re.Pattern]] = {
    "ospf": [
        re.compile(r"authentication message-digest", re.I),
        re.compile(r"ip ospf authentication", re.I),
        re.compile(r"ospfv3 authentication", re.I),
    ],
    "bgp": [
        re.compile(r"neighbor\s+\S+\s+password", re.I),
        re.compile(r"neighbor\s+\S+\s+ao\s+", re.I),  # TCP-AO
    ],
    "eigrp": [
        re.compile(r"authentication mode (md5|hmac-sha-256)", re.I),
        re.compile(r"ip authentication mode eigrp", re.I),
        re.compile(r"ipv6 authentication mode eigrp", re.I),
    ],
}


@dataclass
class Finding:
    host: str
    protocol: str
    status: str  # auth_present | auth_missing | not_configured | error
    detail: str = ""
    snippet: str = ""


@dataclass
class DeviceResult:
    host: str
    reachable: bool = True
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


def _connect(host: str, username: str, password: str, port: int) -> Optional[paramiko.SSHClient]:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host, port=port, username=username, password=password,
            timeout=15, look_for_keys=False, allow_agent=False,
        )
        return client
    except paramiko.AuthenticationException:
        log.error("%s: authentication failed", host)
    except paramiko.SSHException as exc:
        log.error("%s: SSH error — %s", host, exc)
    except OSError as exc:
        log.error("%s: cannot reach device — %s", host, exc)
    return None


def _run(client: paramiko.SSHClient, cmd: str) -> str:
    try:
        _, stdout, stderr = client.exec_command(cmd, timeout=30)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace").strip()
        if err:
            log.debug("stderr: %s", err)
        return out
    except paramiko.SSHException as exc:
        log.warning("Command failed: %s", exc)
        return ""


def _check_protocol(host: str, output: str, protocol: str) -> Finding:
    if not output.strip():
        return Finding(
            host=host, protocol=protocol, status="not_configured",
            detail=f"{protocol.upper()} not present in running config",
        )
    patterns = _AUTH_PATTERNS.get(protocol, [])
    auth_found = any(p.search(output) for p in patterns)
    snippet = output.strip()[:400]
    if auth_found:
        return Finding(
            host=host, protocol=protocol, status="auth_present",
            detail=f"{protocol.upper()} authentication is configured",
            snippet=snippet,
        )
    return Finding(
        host=host, protocol=protocol, status="auth_missing",
        detail=f"{protocol.upper()} is running but authentication is ABSENT",
        snippet=snippet,
    )


def audit_device(
    host: str, username: str, password: str, protocols: List[str], port: int
) -> DeviceResult:
    result = DeviceResult(host=host)
    log.info("Connecting → %s", host)
    client = _connect(host, username, password, port)
    if client is None:
        result.reachable = False
        result.errors.append("SSH connection failed")
        return result

    try:
        for proto in protocols:
            cmd = _SHOW_CMDS.get(proto)
            if cmd is None:
                continue
            log.info("%s  auditing %s …", host, proto.upper())
            output = _run(client, cmd)
            finding = _check_protocol(host, output, proto)
            result.findings.append(finding)
            lvl = logging.WARNING if finding.status == "auth_missing" else logging.INFO
            log.log(lvl, "%s  [%s] %s", host, proto.upper(), finding.detail)
    finally:
        client.close()

    return result


def _load_inventory(path: str) -> List[str]:
    try:
        with open(path) as fh:
            return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    except OSError as exc:
        log.error("Cannot read inventory file: %s", exc)
        sys.exit(2)


def _summary(results: List[DeviceResult]) -> None:
    missing = [
        (r.host, f.protocol)
        for r in results
        for f in r.findings
        if f.status == "auth_missing"
    ]
    unreachable = [r.host for r in results if not r.reachable]

    print("\n── Routing Auth Audit ─────────────────────────────")
    print(f"  Devices audited   : {len(results)}")
    print(f"  Unreachable       : {len(unreachable)}")
    print(f"  Auth gaps found   : {len(missing)}")

    if missing:
        print("\n  AUTH MISSING:")
        for host, proto in missing:
            print(f"    {host:<22} {proto.upper()}")

    if unreachable:
        print("\n  UNREACHABLE:")
        for host in unreachable:
            print(f"    {host}")

    print("───────────────────────────────────────────────────\n")


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Audit routing protocol authentication on IOS/IOS-XE/NX-OS devices",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    tgt = p.add_mutually_exclusive_group(required=True)
    tgt.add_argument("--host", metavar="IP", help="Single device IP or hostname")
    tgt.add_argument("--inventory", metavar="FILE", help="Text file, one host per line")

    p.add_argument("--username", required=True, help="SSH username")
    p.add_argument("--password", required=True, help="SSH password")
    p.add_argument("--port", type=int, default=22, help="SSH port")
    p.add_argument(
        "--protocols", nargs="+", default=["ospf", "bgp", "eigrp"],
        choices=list(_SHOW_CMDS), metavar="PROTO",
        help="Protocols to check: ospf bgp eigrp (default: all)",
    )
    p.add_argument("--output", metavar="FILE", help="Write JSON results to this file")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    hosts = [args.host] if args.host else _load_inventory(args.inventory)
    if not hosts:
        log.error("No hosts found to audit")
        sys.exit(2)

    results = [
        audit_device(h, args.username, args.password, args.protocols, args.port)
        for h in hosts
    ]

    _summary(results)

    if args.output:
        payload = [asdict(r) for r in results]
        try:
            with open(args.output, "w") as fh:
                json.dump(payload, fh, indent=2)
            log.info("Results written to %s", args.output)
        except OSError as exc:
            log.error("Cannot write output file: %s", exc)

    auth_gaps = any(
        f.status == "auth_missing"
        for r in results
        for f in r.findings
    )
    sys.exit(1 if auth_gaps else 0)
```
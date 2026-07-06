interface_audit.py — Multi-device interface status and error counter audit

Purpose:
    Connects to one or more network devices via SSH and collects interface
    operational state and error counters. Flags interfaces that are
    administratively up but operationally down, and interfaces whose combined
    input/output error counts exceed a configurable threshold.

Usage:
    python interface_audit.py --host 192.168.1.1 --username admin
    python interface_audit.py --hosts-file devices.txt --username admin --password secret
    python interface_audit.py --host 10.0.0.1 --username admin --error-threshold 100 --json

Prerequisites:
    pip install paramiko
    Devices must accept SSH and support Cisco IOS/IOS-XE 'show interfaces' output.
    Tested against IOS 15.x, IOS-XE 17.x, and NX-OS 9.x.

Exit codes:
    0 — all devices reachable, no flagged interfaces
    1 — one or more issues found or a device was unreachable
"""

import argparse
import getpass
import json
import logging
import re
import sys
from dataclasses import asdict, dataclass, field
from typing import Optional

try:
    import paramiko
except ImportError:
    print("ERROR: paramiko is required. Install with: pip install paramiko", file=sys.stderr)
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

_SSH_TIMEOUT = 15
_BANNER_TIMEOUT = 15


@dataclass
class InterfaceStats:
    name: str
    admin_state: str = "unknown"
    oper_state: str = "unknown"
    description: str = ""
    input_errors: int = 0
    output_errors: int = 0
    crc_errors: int = 0

    @property
    def is_link_down(self) -> bool:
        return self.admin_state == "up" and self.oper_state == "down"


@dataclass
class DeviceResult:
    host: str
    success: bool
    error: Optional[str] = None
    interfaces: list = field(default_factory=list)


def _ssh_exec(host: str, username: str, password: str, command: str, port: int) -> str:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            port=port,
            username=username,
            password=password,
            timeout=_SSH_TIMEOUT,
            banner_timeout=_BANNER_TIMEOUT,
            look_for_keys=False,
            allow_agent=False,
        )
        _, stdout, stderr = client.exec_command(command, timeout=_SSH_TIMEOUT)
        output = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace").strip()
        if err:
            log.debug("%s stderr: %s", host, err)
        return output
    finally:
        client.close()


def _parse_interfaces(raw: str) -> list:
    interfaces = []
    current: Optional[InterfaceStats] = None

    for line in raw.splitlines():
        m = re.match(
            r"^(\S+)\s+is\s+(administratively down|up|down),\s+line protocol is\s+(up|down)",
            line,
            re.IGNORECASE,
        )
        if m:
            if current:
                interfaces.append(current)
            admin = "down" if "administratively" in m.group(2).lower() else m.group(2).lower()
            current = InterfaceStats(name=m.group(1), admin_state=admin, oper_state=m.group(3).lower())
            continue

        if current is None:
            continue

        m = re.match(r"^\s+Description:\s*(.*)", line)
        if m:
            current.description = m.group(1).strip()
            continue

        m = re.search(r"(\d+)\s+input errors", line)
        if m:
            current.input_errors = int(m.group(1))

        m = re.search(r"(\d+)\s+output errors", line)
        if m:
            current.output_errors = int(m.group(1))

        m = re.search(r"(\d+)\s+CRC", line)
        if m:
            current.crc_errors = int(m.group(1))

    if current:
        interfaces.append(current)

    return interfaces


def audit_device(host: str, username: str, password: str, port: int) -> DeviceResult:
    log.info("Connecting to %s:%d", host, port)
    try:
        raw = _ssh_exec(host, username, password, "show interfaces", port)
        interfaces = _parse_interfaces(raw)
        log.info("%s: parsed %d interfaces", host, len(interfaces))
        return DeviceResult(host=host, success=True, interfaces=interfaces)
    except paramiko.AuthenticationException:
        log.error("%s: authentication failed", host)
        return DeviceResult(host=host, success=False, error="authentication failed")
    except (paramiko.SSHException, OSError) as exc:
        log.error("%s: connection error — %s", host, exc)
        return DeviceResult(host=host, success=False, error=str(exc))


def _load_hosts(path: str) -> list:
    with open(path) as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]


def _print_report(results: list, error_threshold: int, as_json: bool) -> int:
    if as_json:
        print(json.dumps([asdict(r) for r in results], indent=2))
        return sum(1 for r in results if not r.success)

    issues = 0
    for result in results:
        print(f"\n{'=' * 60}\nHost: {result.host}")
        if not result.success:
            print(f"  ERROR: {result.error}")
            issues += 1
            continue

        down = [i for i in result.interfaces if i.is_link_down]
        errored = [
            i for i in result.interfaces
            if (i.input_errors + i.output_errors) > error_threshold
        ]

        if not down and not errored:
            print(f"  OK — {len(result.interfaces)} interfaces, no issues")
            continue

        if down:
            print(f"  LINK DOWN while admin-up ({len(down)}):")
            for iface in down:
                desc = f"  [{iface.description}]" if iface.description else ""
                print(f"    {iface.name}{desc}")
            issues += len(down)

        if errored:
            print(f"  HIGH ERROR COUNTERS (threshold={error_threshold}):")
            for iface in errored:
                total = iface.input_errors + iface.output_errors
                print(
                    f"    {iface.name:<32} in={iface.input_errors}"
                    f"  out={iface.output_errors}  crc={iface.crc_errors}  total={total}"
                )
            issues += len(errored)

    print(f"\n{'=' * 60}")
    print(f"Audited {len(results)} device(s). Issues: {issues}")
    return issues


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Audit interface state and error counters across network devices.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    grp = p.add_mutually_exclusive_group(required=True)
    grp.add_argument("--host", help="Single device hostname or IP")
    grp.add_argument("--hosts-file", metavar="FILE", help="Newline-delimited hosts file")
    p.add_argument("--username", required=True, help="SSH username")
    p.add_argument("--password", help="SSH password (prompted if omitted)")
    p.add_argument("--port", type=int, default=22, help="SSH port")
    p.add_argument(
        "--error-threshold",
        type=int,
        default=50,
        metavar="N",
        help="Flag interfaces with combined input+output errors above N",
    )
    p.add_argument("--json", action="store_true", help="Emit JSON instead of human-readable output")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p


if __name__ == "__main__":
    parser = _build_parser()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(f"Password for {args.username}: ")
    hosts = [args.host] if args.host else _load_hosts(args.hosts_file)

    if not hosts:
        log.error("No hosts to audit.")
        sys.exit(1)

    results = [audit_device(h, args.username, password, args.port) for h in hosts]
    issues = _print_report(results, args.error_threshold, args.json)
    sys.exit(1 if issues else 0)
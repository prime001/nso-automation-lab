bgp_neighbor_audit.py — BGP neighbor state and received-prefix audit

Purpose:
    Connects to one or more Cisco IOS/IOS-XE routers via SSH and collects
    BGP summary data. Reports any neighbor not in Established state and flags
    neighbors whose received-prefix count is below a configurable minimum.
    Useful for rapid post-change verification or scheduled BGP health checks
    in environments without a full NMS.

Usage:
    python bgp_neighbor_audit.py --host 10.0.0.1 --username admin
    python bgp_neighbor_audit.py --hosts-file routers.txt --username admin --password secret
    python bgp_neighbor_audit.py --host 10.0.0.1 --username admin --min-prefixes 1 --json
    python bgp_neighbor_audit.py --host 10.0.0.1 --username admin --vrf MGMT

Prerequisites:
    pip install paramiko
    Devices must accept SSH and support Cisco IOS/IOS-XE
    'show ip bgp summary' output format.  Tested against IOS 15.x and
    IOS-XE 17.x.  Devices with no BGP process are reported as BGP-absent
    (not an error unless --require-bgp is set).

Exit codes:
    0 — all devices reachable, all neighbors Established, prefix counts OK
    1 — one or more neighbors down, device unreachable, or BGP absent on a
        device where --require-bgp was specified
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
    print("ERROR: paramiko is required.  Install with: pip install paramiko", file=sys.stderr)
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

_SSH_TIMEOUT = 15
_BANNER_TIMEOUT = 15
_NON_ESTABLISHED_STATES = {"idle", "active", "connect", "opensent", "openconfirm"}


@dataclass
class BgpNeighbor:
    peer: str
    remote_as: str
    updown: str
    state_or_prefixes: str

    @property
    def is_established(self) -> bool:
        return self.state_or_prefixes.lower() not in _NON_ESTABLISHED_STATES

    @property
    def prefix_count(self) -> Optional[int]:
        try:
            return int(self.state_or_prefixes)
        except ValueError:
            return None


@dataclass
class RouterResult:
    host: str
    success: bool
    bgp_present: bool = False
    local_as: Optional[str] = None
    router_id: Optional[str] = None
    error: Optional[str] = None
    neighbors: list = field(default_factory=list)


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


def _parse_bgp_summary(raw: str) -> tuple:
    """Return (local_as, router_id, [BgpNeighbor]) or (None, None, []) if BGP absent."""
    if "% BGP not active" in raw or "% Invalid" in raw or not raw.strip():
        return None, None, []

    local_as = None
    router_id = None
    neighbors = []

    header_seen = False
    for line in raw.splitlines():
        m = re.search(r"local AS number\s+(\S+)", line)
        if m:
            local_as = m.group(1)

        m = re.search(r"BGP router identifier\s+([\d.]+)", line)
        if m:
            router_id = m.group(1)

        if "State/PfxRcd" in line:
            header_seen = True
            continue

        if not header_seen:
            continue

        # Peer row: IP  V  AS  MsgRcvd  MsgSent  TblVer  InQ  OutQ  Up/Down  State/PfxRcd
        m = re.match(
            r"^\s*([\d.:a-fA-F]+)\s+\d+\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\S+)\s+(\S+)",
            line,
        )
        if m:
            neighbors.append(
                BgpNeighbor(
                    peer=m.group(1),
                    remote_as=m.group(2),
                    updown=m.group(3),
                    state_or_prefixes=m.group(4),
                )
            )

    return local_as, router_id, neighbors


def audit_device(
    host: str, username: str, password: str, port: int, vrf: Optional[str]
) -> RouterResult:
    log.info("Connecting to %s:%d", host, port)
    cmd = "show ip bgp"
    if vrf:
        cmd += f" vpnv4 vrf {vrf}"
    cmd += " summary"

    try:
        raw = _ssh_exec(host, username, password, cmd, port)
    except paramiko.AuthenticationException:
        log.error("%s: authentication failed", host)
        return RouterResult(host=host, success=False, error="authentication failed")
    except (paramiko.SSHException, OSError) as exc:
        log.error("%s: connection error — %s", host, exc)
        return RouterResult(host=host, success=False, error=str(exc))

    local_as, router_id, neighbors = _parse_bgp_summary(raw)
    bgp_present = local_as is not None

    if bgp_present:
        log.info("%s: AS %s, %d neighbor(s)", host, local_as, len(neighbors))
    else:
        log.info("%s: BGP not active", host)

    return RouterResult(
        host=host,
        success=True,
        bgp_present=bgp_present,
        local_as=local_as,
        router_id=router_id,
        neighbors=neighbors,
    )


def _load_hosts(path: str) -> list:
    with open(path) as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]


def _print_report(
    results: list, min_prefixes: int, require_bgp: bool, as_json: bool
) -> int:
    if as_json:
        out = []
        for r in results:
            d = asdict(r)
            d["neighbors"] = [asdict(n) for n in r.neighbors]
            out.append(d)
        print(json.dumps(out, indent=2))
        return sum(1 for r in results if not r.success or (require_bgp and not r.bgp_present))

    issues = 0
    for result in results:
        print(f"\n{'=' * 60}\nHost: {result.host}")
        if not result.success:
            print(f"  ERROR: {result.error}")
            issues += 1
            continue

        if not result.bgp_present:
            status = "WARN — BGP not active" if require_bgp else "INFO — BGP not active"
            print(f"  {status}")
            if require_bgp:
                issues += 1
            continue

        print(f"  Local AS: {result.local_as}   Router-ID: {result.router_id}")

        down = [n for n in result.neighbors if not n.is_established]
        low_pfx = [
            n for n in result.neighbors
            if n.is_established and n.prefix_count is not None and n.prefix_count < min_prefixes
        ]

        if not down and not low_pfx:
            established = len(result.neighbors)
            print(f"  OK — {established} neighbor(s) Established")
            continue

        if down:
            print(f"  NOT ESTABLISHED ({len(down)}):")
            for n in down:
                print(f"    peer={n.peer:<20} AS={n.remote_as:<8} state={n.state_or_prefixes}  updown={n.updown}")
            issues += len(down)

        if low_pfx:
            print(f"  LOW PREFIX COUNT (min={min_prefixes}):")
            for n in low_pfx:
                print(f"    peer={n.peer:<20} AS={n.remote_as:<8} prefixes={n.prefix_count}")
            issues += len(low_pfx)

    print(f"\n{'=' * 60}")
    print(f"Audited {len(results)} device(s).  Issues: {issues}")
    return issues


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Audit BGP neighbor state and received-prefix counts.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    grp = p.add_mutually_exclusive_group(required=True)
    grp.add_argument("--host", help="Single device hostname or IP")
    grp.add_argument("--hosts-file", metavar="FILE", help="Newline-delimited hosts file")
    p.add_argument("--username", required=True, help="SSH username")
    p.add_argument("--password", help="SSH password (prompted if omitted)")
    p.add_argument("--port", type=int, default=22, help="SSH port")
    p.add_argument("--vrf", metavar="NAME", help="VRF name (uses vpnv4 summary)")
    p.add_argument(
        "--min-prefixes",
        type=int,
        default=0,
        metavar="N",
        help="Flag Established neighbors with fewer than N received prefixes",
    )
    p.add_argument(
        "--require-bgp",
        action="store_true",
        help="Treat BGP-absent devices as failures (exit 1)",
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

    results = [
        audit_device(h, args.username, password, args.port, args.vrf)
        for h in hosts
    ]
    issues = _print_report(results, args.min_prefixes, args.require_bgp, args.json)
    sys.exit(1 if issues else 0)
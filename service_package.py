006_config_snapshot.py — Multi-device running-config snapshot and diff tool.

Purpose:
    Pull the running configuration from one or more network devices via SSH,
    write timestamped backups to a local directory, and print a unified diff
    against the most recent previous snapshot for each device.  Designed for
    Cisco IOS/IOS-XE targets but works with any SSH CLI that returns plaintext
    config from "show running-config".

Usage:
    python 006_config_snapshot.py --hosts 10.0.0.1 10.0.0.2 \
        --username admin --password secret --output-dir ./snapshots

    # Supply a host-file (one IP/hostname per line, # = comment):
    python 006_config_snapshot.py --host-file devices.txt \
        --username admin --key-file ~/.ssh/id_rsa --output-dir ./snapshots

Prerequisites:
    pip install paramiko
    SSH reachability on port 22 (or override with --port).
    Account with privilege sufficient to run "show running-config".
"""

import argparse
import difflib
import glob
import logging
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import paramiko

LOG_FORMAT = "%(asctime)s  %(levelname)-8s  %(message)s"
logging.basicConfig(format=LOG_FORMAT, level=logging.INFO)
log = logging.getLogger(__name__)

_SHOW_CMD = "show running-config\n"
_RECV_TIMEOUT = 12.0


def fetch_config(
    host: str,
    port: int,
    username: str,
    password: Optional[str],
    key_file: Optional[str],
    timeout: int,
) -> str:
    """Open an interactive SSH shell and return the running-config text."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs: dict = dict(
        hostname=host,
        port=port,
        username=username,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    if key_file:
        connect_kwargs["key_filename"] = key_file
    else:
        connect_kwargs["password"] = password

    try:
        client.connect(**connect_kwargs)
        channel = client.invoke_shell()
        time.sleep(1.0)

        channel.send("terminal length 0\n")
        time.sleep(0.5)
        if channel.recv_ready():
            channel.recv(4096)

        channel.send(_SHOW_CMD)

        output = b""
        deadline = time.time() + _RECV_TIMEOUT
        while time.time() < deadline:
            if channel.recv_ready():
                output += channel.recv(65535)
                deadline = time.time() + 2.0
            else:
                time.sleep(0.2)

        return output.decode("utf-8", errors="replace")
    finally:
        client.close()


def latest_snapshot(snapshot_dir: Path, host: str) -> Optional[Path]:
    """Return the most recent snapshot file for *host*, or None."""
    matches = sorted(glob.glob(str(snapshot_dir / f"{host}_*.cfg")))
    return Path(matches[-1]) if matches else None


def save_snapshot(snapshot_dir: Path, host: str, config: str) -> Path:
    """Write config to a timestamped file and return its path."""
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    out = snapshot_dir / f"{host}_{ts}.cfg"
    out.write_text(config, encoding="utf-8")
    return out


def diff_configs(old_path: Optional[Path], new_path: Path) -> List[str]:
    """Return unified-diff lines comparing old and new snapshots."""
    new_lines = new_path.read_text(encoding="utf-8").splitlines(keepends=True)
    if old_path is None:
        return (
            ["--- (no previous snapshot)\n", f"+++ {new_path.name}\n",
             "@@ first snapshot — all lines added @@\n"]
            + [f"+{l}" for l in new_lines]
        )
    old_lines = old_path.read_text(encoding="utf-8").splitlines(keepends=True)
    return list(
        difflib.unified_diff(old_lines, new_lines,
                             fromfile=old_path.name, tofile=new_path.name)
    )


def snapshot_device(host: str, args: argparse.Namespace, snapshot_dir: Path) -> dict:
    """Fetch, save, and diff the running config for one device."""
    result = {"host": host, "status": "ok", "changed": False, "error": None}
    try:
        log.info("[%s] connecting …", host)
        config = fetch_config(
            host=host,
            port=args.port,
            username=args.username,
            password=getattr(args, "password", None),
            key_file=getattr(args, "key_file", None),
            timeout=args.timeout,
        )

        old_snap = latest_snapshot(snapshot_dir, host)
        new_snap = save_snapshot(snapshot_dir, host, config)
        log.info("[%s] saved → %s", host, new_snap.name)

        diff = diff_configs(old_snap, new_snap)
        result["changed"] = old_snap is None or bool(diff)

        if diff:
            sep = "=" * 72
            sys.stdout.write(f"\n{sep}\nDIFF: {host}\n{sep}\n")
            sys.stdout.writelines(diff)
        else:
            log.info("[%s] no change since last snapshot", host)

    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        log.error("[%s] %s", host, exc)

    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Snapshot running configs and diff against previous backup.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    host_group = parser.add_mutually_exclusive_group(required=True)
    host_group.add_argument("--hosts", nargs="+", metavar="HOST",
                            help="One or more device IPs or hostnames.")
    host_group.add_argument("--host-file", metavar="FILE",
                            help="Text file with one host per line (# = comment).")

    parser.add_argument("--username", required=True, help="SSH username.")

    cred = parser.add_mutually_exclusive_group(required=True)
    cred.add_argument("--password", help="SSH password.")
    cred.add_argument("--key-file", metavar="FILE", help="Path to SSH private key.")

    parser.add_argument("--port", type=int, default=22, help="SSH port.")
    parser.add_argument("--timeout", type=int, default=30,
                        help="SSH connection timeout in seconds.")
    parser.add_argument("--output-dir", default="./snapshots",
                        help="Directory for snapshot files.")
    parser.add_argument("--workers", type=int, default=5,
                        help="Maximum concurrent SSH sessions.")
    parser.add_argument("--debug", action="store_true",
                        help="Enable DEBUG-level logging.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.DEBUG)

    if args.hosts:
        hosts = args.hosts
    else:
        host_file = Path(args.host_file)
        if not host_file.exists():
            log.error("Host file not found: %s", host_file)
            return 1
        hosts = [
            line.strip()
            for line in host_file.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]

    if not hosts:
        log.error("No hosts to process.")
        return 1

    snapshot_dir = Path(args.output_dir)
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    log.info("Snapshot directory: %s", snapshot_dir.resolve())
    log.info("Processing %d device(s) with up to %d workers.", len(hosts), args.workers)

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(snapshot_device, host, args, snapshot_dir): host
            for host in hosts
        }
        for fut in as_completed(futures):
            results.append(fut.result())

    ok = sum(1 for r in results if r["status"] == "ok")
    changed = sum(1 for r in results if r.get("changed"))
    errors = len(results) - ok

    log.info("Summary — %d OK (%d with changes), %d error(s).", ok, changed, errors)
    for r in results:
        if r["status"] == "error":
            log.warning("  FAILED  %s — %s", r["host"], r["error"])

    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
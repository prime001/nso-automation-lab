```python
"""
031_config_backup.py - Network Device Configuration Backup with Rotation and Diff

Purpose:
    Connects to network devices via SSH, retrieves the running configuration,
    stores it with a UTC timestamp, enforces a retention window by rotating old
    backups, and optionally prints a unified diff against the previous backup so
    operators can spot unexpected drift at a glance.

Usage:
    # Single device, password auth
    python 031_config_backup.py --host 192.168.1.1 --user admin --password secret

    # Single device, key auth, custom command, show diff
    python 031_config_backup.py --host 192.168.1.1 --user admin \
        --key-file ~/.ssh/id_rsa --diff

    # Multiple devices from a file, keep 14 backups per host
    python 031_config_backup.py --host-file devices.txt --user admin --keep 14

    devices.txt format: one hostname or IP per line; lines starting with # are ignored.

Prerequisites:
    pip install paramiko
    SSH access to target devices (password or key-based)
    Devices must honour 'show running-config' or the command supplied via --command
"""

import argparse
import difflib
import getpass
import logging
import sys
from pathlib import Path
from datetime import datetime, timezone

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

DEFAULT_COMMAND = "show running-config"


def ssh_connect(
    host: str,
    user: str,
    password: str | None,
    key_file: str | None,
    port: int,
) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs: dict = {"hostname": host, "port": port, "username": user, "timeout": 30}
    if key_file:
        kwargs["key_filename"] = key_file
    else:
        kwargs["password"] = password
        kwargs["look_for_keys"] = False
    client.connect(**kwargs)
    return client


def fetch_config(client: paramiko.SSHClient, command: str) -> str:
    _, stdout, stderr = client.exec_command(command, timeout=60)
    output = stdout.read().decode("utf-8", errors="replace").strip()
    err = stderr.read().decode("utf-8", errors="replace").strip()
    if err:
        log.debug("stderr from device: %s", err)
    return output


def host_dir(backup_root: Path, host: str) -> Path:
    d = backup_root / host
    d.mkdir(parents=True, exist_ok=True)
    return d


def timestamped_path(d: Path, host: str) -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return d / f"{host}_{ts}.cfg"


def latest_backup(d: Path) -> Path | None:
    candidates = sorted(d.glob("*.cfg"))
    return candidates[-1] if candidates else None


def rotate(d: Path, keep: int) -> int:
    all_backups = sorted(d.glob("*.cfg"))
    excess = all_backups[: max(0, len(all_backups) - keep)]
    for path in excess:
        path.unlink()
        log.debug("Rotated: %s", path.name)
    return len(excess)


def show_diff(prev_path: Path, new_content: str, host: str) -> None:
    old_lines = prev_path.read_text(encoding="utf-8").splitlines(keepends=True)
    new_lines = new_content.splitlines(keepends=True)
    delta = list(
        difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile=prev_path.name,
            tofile="current",
            lineterm="",
        )
    )
    if delta:
        log.info("Config drift detected on %s (%d diff lines):", host, len(delta))
        sys.stdout.write("".join(delta) + "\n")
    else:
        log.info("No config changes detected for %s", host)


def backup_device(
    host: str,
    user: str,
    password: str | None,
    backup_root: Path,
    key_file: str | None = None,
    port: int = 22,
    command: str = DEFAULT_COMMAND,
    keep: int = 30,
    diff: bool = False,
) -> bool:
    log.info("[%s] Connecting on port %d", host, port)
    try:
        client = ssh_connect(host, user, password, key_file, port)
    except Exception as exc:
        log.error("[%s] Connection failed: %s", host, exc)
        return False

    try:
        config = fetch_config(client, command)
    except Exception as exc:
        log.error("[%s] Config fetch failed: %s", host, exc)
        return False
    finally:
        client.close()

    if not config:
        log.warning("[%s] Empty config returned; skipping.", host)
        return False

    d = host_dir(backup_root, host)
    prev = latest_backup(d)

    if diff and prev:
        show_diff(prev, config, host)

    out = timestamped_path(d, host)
    out.write_text(config, encoding="utf-8")
    log.info("[%s] Saved %s (%d bytes)", host, out.name, out.stat().st_size)

    removed = rotate(d, keep)
    if removed:
        log.info("[%s] Rotated %d old backup(s)", host, removed)

    return True


def load_host_file(path: str) -> list[str]:
    p = Path(path)
    if not p.exists():
        log.error("Host file not found: %s", path)
        return []
    return [
        line.strip()
        for line in p.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Back up network device running configurations.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--host", help="Single device hostname or IP")
    group.add_argument("--host-file", metavar="FILE", help="File with one host per line")
    parser.add_argument("--user", required=True, help="SSH username")
    parser.add_argument("--password", default=None, help="SSH password")
    parser.add_argument("--key-file", default=None, metavar="PATH", help="SSH private key file")
    parser.add_argument("--port", type=int, default=22, help="SSH port")
    parser.add_argument("--command", default=DEFAULT_COMMAND, help="Config retrieval command")
    parser.add_argument("--backup-dir", default="./backups", metavar="DIR",
                        help="Root directory for backup storage")
    parser.add_argument("--keep", type=int, default=30,
                        help="Backups to retain per host")
    parser.add_argument("--diff", action="store_true",
                        help="Print unified diff against previous backup")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.password and not args.key_file:
        args.password = getpass.getpass(f"Password for {args.user}@: ")

    hosts = [args.host] if args.host else load_host_file(args.host_file)
    if not hosts:
        log.error("No hosts to process.")
        sys.exit(1)

    ok_count = fail_count = 0
    for host in hosts:
        success = backup_device(
            host=host,
            user=args.user,
            password=args.password,
            backup_root=Path(args.backup_dir),
            key_file=args.key_file,
            port=args.port,
            command=args.command,
            keep=args.keep,
            diff=args.diff,
        )
        if success:
            ok_count += 1
        else:
            fail_count += 1

    log.info("Finished. Success: %d  Failed: %d", ok_count, fail_count)
    sys.exit(0 if fail_count == 0 else 1)
```
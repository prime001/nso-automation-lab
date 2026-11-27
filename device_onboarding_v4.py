```python
"""
034_ssh_key_deployment.py — SSH Key Pre-Staging and Reachability Validator

Purpose:
    Before onboarding devices into NSO, verify SSH reachability and optionally
    deploy an SSH public key for key-based authentication. Produces a CSV report
    of reachability status and key deployment results.

Usage:
    # Single device, reachability check only
    python 034_ssh_key_deployment.py --host 10.0.0.1 --user admin --password s3cr3t

    # Single device, deploy SSH public key
    python 034_ssh_key_deployment.py --host 10.0.0.1 --user admin --password s3cr3t \
        --pubkey ~/.ssh/id_rsa.pub

    # Batch mode from CSV (columns: host,username,password)
    python 034_ssh_key_deployment.py --inventory devices.csv --pubkey ~/.ssh/id_rsa.pub \
        --output results.csv

Prerequisites:
    pip install paramiko
    SSH must be enabled on target devices.
    User must have shell access to append to ~/.ssh/authorized_keys.
"""

import argparse
import csv
import logging
import socket
import subprocess
import sys
from dataclasses import dataclass, fields
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


@dataclass
class DeviceResult:
    host: str
    username: str
    ping_ok: bool
    ssh_ok: bool
    key_deployed: bool
    error: str = ""


def ping(host: str, timeout: int = 2) -> bool:
    result = subprocess.run(
        ["ping", "-c", "1", "-W", str(timeout), host],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def check_ssh_port(host: str, port: int = 22, timeout: int = 5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def deploy_pubkey(host: str, username: str, password: str, pubkey: str, port: int = 22) -> tuple[bool, str]:
    """
    Connect via SSH and append pubkey to ~/.ssh/authorized_keys if not already present.
    Returns (success, error_message).
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username=username, password=password, timeout=10, look_for_keys=False)
        pubkey_stripped = pubkey.strip()

        setup_cmd = (
            "mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
            "touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
        )
        _, stdout, stderr = client.exec_command(setup_cmd)
        if stdout.channel.recv_exit_status() != 0:
            return False, stderr.read().decode().strip()

        check_cmd = f"grep -qF '{pubkey_stripped}' ~/.ssh/authorized_keys"
        _, _, _ = client.exec_command(check_cmd)
        already_present = _.channel.recv_exit_status() == 0

        if already_present:
            log.info("%s: public key already present, skipping", host)
            return True, ""

        append_cmd = f"echo '{pubkey_stripped}' >> ~/.ssh/authorized_keys"
        _, stdout, stderr = client.exec_command(append_cmd)
        if stdout.channel.recv_exit_status() != 0:
            return False, stderr.read().decode().strip()

        return True, ""
    except paramiko.AuthenticationException as exc:
        return False, f"auth failed: {exc}"
    except paramiko.SSHException as exc:
        return False, f"ssh error: {exc}"
    except OSError as exc:
        return False, f"connect error: {exc}"
    finally:
        client.close()


def process_device(host: str, username: str, password: str, pubkey: str | None, port: int) -> DeviceResult:
    result = DeviceResult(host=host, username=username, ping_ok=False, ssh_ok=False, key_deployed=False)

    log.info("Checking %s ...", host)
    result.ping_ok = ping(host)
    if not result.ping_ok:
        log.warning("%s: no ping response", host)

    result.ssh_ok = check_ssh_port(host, port=port)
    if not result.ssh_ok:
        result.error = "TCP port unreachable"
        log.warning("%s: SSH port %d unreachable", host, port)
        return result

    if pubkey:
        result.key_deployed, result.error = deploy_pubkey(host, username, password, pubkey, port)
        if result.key_deployed:
            log.info("%s: key deployed successfully", host)
        else:
            log.error("%s: key deployment failed: %s", host, result.error)
    else:
        result.key_deployed = False

    return result


def write_csv(results: list[DeviceResult], output_path: str) -> None:
    header = [f.name for f in fields(DeviceResult)]
    with open(output_path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=header)
        writer.writeheader()
        for r in results:
            writer.writerow({f.name: getattr(r, f.name) for f in fields(DeviceResult)})
    log.info("Results written to %s", output_path)


def load_inventory(csv_path: str) -> list[dict]:
    with open(csv_path, newline="") as fh:
        return list(csv.DictReader(fh))


def main() -> int:
    parser = argparse.ArgumentParser(description="SSH key pre-staging and reachability validator")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--host", help="Target device IP or hostname")
    group.add_argument("--inventory", metavar="CSV", help="CSV file with columns: host,username,password")
    parser.add_argument("--user", help="SSH username (single-device mode)")
    parser.add_argument("--password", help="SSH password (single-device mode)")
    parser.add_argument("--pubkey", metavar="FILE", help="Path to SSH public key to deploy")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--output", metavar="CSV", help="Write results to CSV file")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.WARNING)

    pubkey_content = None
    if args.pubkey:
        pubkey_content = Path(args.pubkey).read_text().strip()

    if args.host:
        if not args.user or not args.password:
            parser.error("--user and --password are required with --host")
        devices = [{"host": args.host, "username": args.user, "password": args.password}]
    else:
        devices = load_inventory(args.inventory)

    results = []
    for dev in devices:
        result = process_device(
            host=dev["host"],
            username=dev["username"],
            password=dev["password"],
            pubkey=pubkey_content,
            port=args.port,
        )
        results.append(result)

    reachable = sum(1 for r in results if r.ssh_ok)
    deployed = sum(1 for r in results if r.key_deployed)
    log.info("Summary: %d/%d reachable, %d/%d keys deployed", reachable, len(results), deployed, len(results))

    if args.output:
        write_csv(results, args.output)

    failed = [r for r in results if not r.ssh_ok or (pubkey_content and not r.key_deployed)]
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
```
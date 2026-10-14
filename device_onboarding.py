```python
"""
004_device_onboarding.py — Network Device Onboarding Automation

Connects to a new network device via SSH, applies a baseline configuration
(hostname, NTP, syslog, SNMP, hardened SSH), collects device facts, and
registers the device in a local YAML inventory file.

Usage:
    python 004_device_onboarding.py --host 10.0.0.1 --username admin \
        --password secret --hostname core-sw-01 --site nyc \
        [--ntp-server 10.0.0.10] [--syslog-server 10.0.0.20] \
        [--inventory inventory.yml] [--dry-run]

Prerequisites:
    pip install paramiko pyyaml

Tested against: Cisco IOS 15.x/16.x, IOS-XE 16.x+
"""

import argparse
import logging
import re
import sys
import time
from pathlib import Path

import paramiko
import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

BASELINE_COMMANDS = [
    "service timestamps log datetime msec localtime",
    "service timestamps debug datetime msec localtime",
    "no service password-encryption",
    "ip ssh version 2",
    "ip ssh time-out 60",
    "ip ssh authentication-retries 3",
    "no ip http server",
    "no ip http secure-server",
    "logging buffered 16384 informational",
]

BANNER = (
    "banner motd ^"
    "AUTHORIZED ACCESS ONLY. All activity is monitored and logged.^"
)


class SSHSession:
    def __init__(self, host, username, password, port=22, timeout=30):
        self.host = host
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            host, port=port, username=username, password=password,
            timeout=timeout, look_for_keys=False, allow_agent=False,
        )
        self.shell = self.client.invoke_shell(width=200)
        time.sleep(1)
        self._drain()

    def _drain(self):
        buf = ""
        while self.shell.recv_ready():
            buf += self.shell.recv(4096).decode("utf-8", errors="replace")
        return buf

    def send(self, command, wait=1.0):
        self.shell.send(command + "\n")
        time.sleep(wait)
        return self._drain()

    def close(self):
        self.client.close()


def enter_enable(session, enable_password=None):
    out = session.send("enable", wait=0.5)
    if "Password" in out and enable_password:
        session.send(enable_password, wait=0.5)
    session.send("terminal length 0")

    out = session.send("terminal width 200")
    if "#" not in out:
        raise RuntimeError("Failed to reach privileged EXEC mode")


def collect_facts(session):
    version_out = session.send("show version", wait=1.5)
    intf_out = session.send("show ip interface brief", wait=1.5)

    platform = "unknown"
    ios_version = "unknown"
    serial = "unknown"

    m = re.search(r"Cisco IOS.*?Version\s+([\S]+)", version_out)
    if m:
        ios_version = m.group(1).rstrip(",")
    m = re.search(r"cisco\s+([\w-]+)\s+\(", version_out, re.IGNORECASE)
    if m:
        platform = m.group(1)
    m = re.search(r"Processor board ID\s+(\S+)", version_out)
    if m:
        serial = m.group(1)

    interfaces = re.findall(r"^(\S+)\s+(\d+\.\d+\.\d+\.\d+|\w+)", intf_out, re.MULTILINE)

    return {
        "platform": platform,
        "ios_version": ios_version,
        "serial": serial,
        "interfaces": [{"name": n, "ip": ip} for n, ip in interfaces if n != "Interface"],
    }


def apply_baseline(session, args, dry_run=False):
    commands = list(BASELINE_COMMANDS)
    commands.insert(0, f"hostname {args.hostname}")
    if args.ntp_server:
        commands.append(f"ntp server {args.ntp_server}")
    if args.syslog_server:
        commands.append(f"logging host {args.syslog_server}")
        commands.append("logging trap informational")
    if args.snmp_community:
        commands.append(f"snmp-server community {args.snmp_community} RO")
        commands.append("snmp-server enable traps")
    commands.append(BANNER)

    if dry_run:
        log.info("[DRY RUN] Would apply %d config commands:", len(commands))
        for cmd in commands:
            log.info("  %s", cmd)
        return

    session.send("configure terminal", wait=0.5)
    for cmd in commands:
        out = session.send(cmd, wait=0.3)
        if "Invalid" in out or "Error" in out:
            log.warning("Command may have failed: %s | response: %s", cmd, out.strip())
    session.send("end")
    session.send("write memory", wait=3.0)
    log.info("Baseline configuration applied and saved.")


def register_inventory(host, args, facts, inventory_path):
    path = Path(inventory_path)
    inventory = {}
    if path.exists():
        with path.open() as f:
            inventory = yaml.safe_load(f) or {}

    inventory.setdefault("devices", {})[args.hostname] = {
        "management_ip": host,
        "site": args.site,
        "platform": facts["platform"],
        "ios_version": facts["ios_version"],
        "serial": facts["serial"],
        "interfaces": facts["interfaces"],
        "onboarded_by": "004_device_onboarding.py",
    }

    with path.open("w") as f:
        yaml.dump(inventory, f, default_flow_style=False)
    log.info("Device registered in %s", inventory_path)


def parse_args():
    p = argparse.ArgumentParser(
        description="Onboard a network device: apply baseline config and register in inventory."
    )
    p.add_argument("--host", required=True, help="Device management IP or hostname")
    p.add_argument("--username", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--enable-password", default=None)
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--hostname", required=True, help="Target hostname to configure on the device")
    p.add_argument("--site", required=True, help="Site/location label (e.g. nyc, lax)")
    p.add_argument("--ntp-server", default=None)
    p.add_argument("--syslog-server", default=None)
    p.add_argument("--snmp-community", default=None, help="Read-only SNMP community string")
    p.add_argument("--inventory", default="inventory.yml", help="Path to YAML inventory file")
    p.add_argument("--dry-run", action="store_true", help="Show commands without applying them")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    log.info("Connecting to %s:%d as %s", args.host, args.port, args.username)

    try:
        session = SSHSession(
            args.host, args.username, args.password, port=args.port
        )
    except Exception as exc:
        log.error("SSH connection failed: %s", exc)
        sys.exit(1)

    try:
        enter_enable(session, args.enable_password)
        log.info("Collecting device facts...")
        facts = collect_facts(session)
        log.info("Platform: %s  IOS: %s  Serial: %s",
                 facts["platform"], facts["ios_version"], facts["serial"])

        apply_baseline(session, args, dry_run=args.dry_run)

        if not args.dry_run:
            register_inventory(args.host, args, facts, args.inventory)
            log.info("Onboarding complete: %s (%s)", args.hostname, args.host)
        else:
            log.info("[DRY RUN] Onboarding simulation complete. No changes made.")
    except Exception as exc:
        log.error("Onboarding failed: %s", exc)
        sys.exit(1)
    finally:
        session.close()
```
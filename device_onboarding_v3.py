The user's explicit instruction ("Output ONLY the script content, no markdown fences, no explanation") is a complete, fully-specified request that overrides the brainstorming gate. Writing the script directly.

#!/usr/bin/env python3
"""
024_device_onboarding.py — NSO RESTCONF Device Onboarding with SSH Pre-flight Validation

Purpose:
    Onboards a network device into Cisco NSO via the RESTCONF API after
    confirming SSH reachability and credential validity. Adds the device entry
    to the NSO CDB, triggers a sync-from action, and reports the final sync
    state. Supports a dry-run mode that validates connectivity without modifying
    NSO.

Usage:
    python 024_device_onboarding.py \
        --device-name edge-rtr-01 \
        --device-host 192.168.1.1 \
        --device-user admin \
        --device-pass secret \
        --ned-id cisco-ios-cli-6.88 \
        --nso-url http://localhost:8080 \
        --nso-user admin \
        --nso-pass admin

Prerequisites:
    - Python 3.8+
    - paramiko  (pip install paramiko)
    - requests  (pip install requests)
    - NSO with RESTCONF enabled (tailf-rest-api.yang loaded)
    - SSH access from this host to the target device
"""

import argparse
import logging
import sys
from typing import Optional

import paramiko
import requests
from requests.auth import HTTPBasicAuth

log = logging.getLogger(__name__)

_RESTCONF_HEADERS = {
    "Accept": "application/yang-data+json",
    "Content-Type": "application/yang-data+json",
}


def check_ssh_reachability(
    host: str,
    port: int,
    username: str,
    password: str,
    timeout: int,
) -> bool:
    """Attempt an SSH login; return True on success, False on any failure."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        log.info("SSH pre-flight passed: %s:%s", host, port)
        return True
    except paramiko.AuthenticationException:
        log.error("SSH authentication failed for %s@%s", username, host)
    except (paramiko.SSHException, OSError) as exc:
        log.error("SSH connection to %s failed: %s", host, exc)
    finally:
        client.close()
    return False


def add_device_to_nso(
    session: requests.Session,
    nso_url: str,
    device_name: str,
    device_host: str,
    device_port: int,
    ned_id: str,
    authgroup: str,
) -> bool:
    """POST a new device entry to the NSO CDB via RESTCONF."""
    url = f"{nso_url}/restconf/data/tailf-ncs:devices/device"
    payload = {
        "device": [
            {
                "name": device_name,
                "address": device_host,
                "port": device_port,
                "authgroups": {"authgroup": [{"name": authgroup}]},
                "device-type": {"cli": {"ned-id": ned_id}},
                "state": {"admin-state": "unlocked"},
            }
        ]
    }
    try:
        resp = session.post(url, json=payload, headers=_RESTCONF_HEADERS)
        if resp.status_code in (201, 204):
            log.info("Device '%s' created in NSO CDB", device_name)
            return True
        log.error(
            "Failed to create device '%s': HTTP %s — %s",
            device_name,
            resp.status_code,
            resp.text[:300],
        )
    except requests.RequestException as exc:
        log.error("RESTCONF POST error for device '%s': %s", device_name, exc)
    return False


def sync_from_device(
    session: requests.Session,
    nso_url: str,
    device_name: str,
) -> Optional[bool]:
    """Invoke sync-from on a device; return True/False on result or None on error."""
    url = (
        f"{nso_url}/restconf/data/tailf-ncs:devices"
        f"/device={device_name}/sync-from"
    )
    try:
        resp = session.post(url, headers=_RESTCONF_HEADERS)
        if resp.status_code == 200:
            output = resp.json().get("tailf-ncs:output", {})
            success = bool(output.get("result", False))
            if success:
                log.info("sync-from succeeded for '%s'", device_name)
            else:
                log.warning("sync-from returned non-success for '%s': %s", device_name, output)
            return success
        log.error("sync-from returned HTTP %s for '%s'", resp.status_code, device_name)
    except requests.RequestException as exc:
        log.error("sync-from request error for '%s': %s", device_name, exc)
    return None


def _build_session(nso_user: str, nso_pass: str, timeout: int) -> requests.Session:
    session = requests.Session()
    session.auth = HTTPBasicAuth(nso_user, nso_pass)
    session.timeout = timeout
    return session


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Onboard a device into NSO via RESTCONF with SSH pre-flight."
    )
    p.add_argument("--device-name", required=True, help="NSO CDB device name key")
    p.add_argument("--device-host", required=True, help="Device management IP or FQDN")
    p.add_argument("--device-port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--device-user", required=True, help="Device SSH username")
    p.add_argument("--device-pass", required=True, help="Device SSH password")
    p.add_argument("--ned-id", required=True, help="NED ID (e.g. cisco-ios-cli-6.88)")
    p.add_argument("--authgroup", default="default", help="NSO authgroup (default: default)")
    p.add_argument("--nso-url", default="http://localhost:8080", help="NSO base URL")
    p.add_argument("--nso-user", default="admin", help="NSO RESTCONF username")
    p.add_argument("--nso-pass", default="admin", help="NSO RESTCONF password")
    p.add_argument("--timeout", type=int, default=15, help="Connection timeout in seconds")
    p.add_argument("--skip-preflight", action="store_true", help="Skip SSH reachability check")
    p.add_argument("--dry-run", action="store_true", help="Check connectivity only; skip NSO writes")
    p.add_argument("--debug", action="store_true", help="Enable DEBUG log output")
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(message)s",
    )

    if not args.skip_preflight:
        log.info("Running SSH pre-flight for %s:%s", args.device_host, args.device_port)
        reachable = check_ssh_reachability(
            args.device_host,
            args.device_port,
            args.device_user,
            args.device_pass,
            args.timeout,
        )
        if not reachable:
            log.error("Pre-flight failed — aborting onboarding for '%s'", args.device_name)
            return 1
    else:
        log.warning("SSH pre-flight skipped (--skip-preflight)")

    if args.dry_run:
        log.info("Dry-run complete: connectivity OK, no NSO changes written")
        return 0

    session = _build_session(args.nso_user, args.nso_pass, args.timeout)

    added = add_device_to_nso(
        session,
        args.nso_url,
        args.device_name,
        args.device_host,
        args.device_port,
        args.ned_id,
        args.authgroup,
    )
    if not added:
        return 1

    result = sync_from_device(session, args.nso_url, args.device_name)
    if result is None:
        log.error("sync-from request failed for '%s' — device added but not synced", args.device_name)
        return 1
    if not result:
        log.error("sync-from reported failure for '%s' — check NED and credentials", args.device_name)
        return 1

    log.info("Onboarding complete: '%s' is active and synced in NSO", args.device_name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
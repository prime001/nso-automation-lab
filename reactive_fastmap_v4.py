```
"""
032_reactive_fastmap.py — NSO Device Sync Watchdog (Reactive Fastmap)

Purpose:
    Implements a reactive fastmap pattern that continuously monitors device
    sync status via NSO RESTCONF API and automatically triggers sync-from
    operations when devices drift out of sync with the CDB.

    The script polls the NSO device list, identifies stale or out-of-sync
    devices, and emits structured remediation events — mirroring how an NSO
    reactive fastmap Python component subscribes to kicker notifications
    and re-applies service logic on CDB changes.

Usage:
    python 032_reactive_fastmap.py --host 192.168.1.1 --user admin \
        --password secret --interval 60 --threshold 3

    Dry-run (log actions without executing):
        python 032_reactive_fastmap.py --host 192.168.1.1 --user admin \
            --password secret --dry-run --once

Prerequisites:
    - NSO instance with RESTCONF enabled (default port 8080)
    - Device NEDs installed and devices onboarded in NSO
    - Python 3.9+ (stdlib only: urllib, argparse, logging, dataclasses)
"""

import argparse
import base64
import json
import logging
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,
)
log = logging.getLogger("sync-watchdog")


@dataclass
class SyncEvent:
    device: str
    sync_state: str
    timestamp: str
    remediation_attempted: bool = False
    remediation_result: Optional[str] = None


@dataclass
class WatchdogState:
    drift_counts: dict = field(default_factory=dict)
    events: list = field(default_factory=list)


def build_headers(username: str, password: str) -> dict:
    creds = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {
        "Authorization": f"Basic {creds}",
        "Accept": "application/yang-data+json",
        "Content-Type": "application/yang-data+json",
    }


def restconf_get(host: str, port: int, path: str, headers: dict) -> dict:
    url = f"http://{host}:{port}/restconf/data/{path}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"GET {path} failed: {exc.code} {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Unreachable at {host}:{port}: {exc.reason}") from exc


def restconf_post(host: str, port: int, path: str, headers: dict) -> dict:
    url = f"http://{host}:{port}/restconf/operations/{path}"
    data = json.dumps({}).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read()
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"POST {path} failed: {exc.code} {exc.reason}") from exc


def fetch_device_sync_status(host: str, port: int, headers: dict) -> list:
    data = restconf_get(host, port, "tailf-ncs:devices/device", headers)
    results = []
    for dev in data.get("tailf-ncs:device", []):
        results.append({
            "name": dev.get("name", "unknown"),
            "sync_state": dev.get("state", {}).get("sync-state", "unknown"),
        })
    return results


def trigger_sync_from(host: str, port: int, device: str, headers: dict) -> str:
    path = f"tailf-ncs:devices/device={device}/sync-from"
    result = restconf_post(host, port, path, headers)
    return result.get("tailf-ncs:output", {}).get("result", "unknown")


def process_poll(
    devices: list,
    state: WatchdogState,
    host: str,
    port: int,
    headers: dict,
    threshold: int,
    dry_run: bool,
) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    for dev in devices:
        name = dev["name"]
        sync_state = dev["sync_state"]

        if sync_state == "in-sync":
            if name in state.drift_counts:
                log.info("Device %s recovered (back in-sync)", name)
                del state.drift_counts[name]
            continue

        count = state.drift_counts.get(name, 0) + 1
        state.drift_counts[name] = count
        log.warning(
            "Device %s out-of-sync (state=%s, consecutive=%d/%d)",
            name, sync_state, count, threshold,
        )

        evt = SyncEvent(device=name, sync_state=sync_state, timestamp=ts)
        if count >= threshold:
            if dry_run:
                log.info("[dry-run] Would trigger sync-from for %s", name)
                evt.remediation_attempted = True
                evt.remediation_result = "dry-run"
            else:
                log.info("Triggering sync-from for %s", name)
                try:
                    result = trigger_sync_from(host, port, name, headers)
                    evt.remediation_attempted = True
                    evt.remediation_result = result
                    log.info("sync-from %s result: %s", name, result)
                    if result == "true":
                        state.drift_counts[name] = 0
                except RuntimeError as exc:
                    evt.remediation_result = f"error: {exc}"
                    log.error("sync-from failed for %s: %s", name, exc)

        state.events.append(evt)


def run_watchdog(args: argparse.Namespace) -> None:
    headers = build_headers(args.user, args.password)
    state = WatchdogState()

    log.info(
        "Starting sync watchdog — host=%s port=%d interval=%ds threshold=%d dry_run=%s",
        args.host, args.port, args.interval, args.threshold, args.dry_run,
    )

    iteration = 0
    while True:
        iteration += 1
        log.debug("Poll iteration %d", iteration)
        try:
            devices = fetch_device_sync_status(args.host, args.port, headers)
            log.debug("Fetched %d devices", len(devices))
            process_poll(
                devices, state, args.host, args.port, headers,
                args.threshold, args.dry_run,
            )
        except RuntimeError as exc:
            log.error("Poll error: %s", exc)

        if args.once:
            log.info("Single poll complete (%d events recorded)", len(state.events))
            break

        time.sleep(args.interval)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="NSO reactive fastmap: device sync watchdog with auto-remediation"
    )
    p.add_argument("--host", required=True, help="NSO host or IP address")
    p.add_argument("--port", type=int, default=8080, help="RESTCONF port (default: 8080)")
    p.add_argument("--user", required=True, help="NSO username")
    p.add_argument("--password", required=True, help="NSO password")
    p.add_argument(
        "--interval", type=int, default=60,
        help="Poll interval in seconds (default: 60)",
    )
    p.add_argument(
        "--threshold", type=int, default=3,
        help="Consecutive out-of-sync polls before triggering remediation (default: 3)",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Log what would happen without executing sync-from operations",
    )
    p.add_argument(
        "--once", action="store_true",
        help="Run a single poll and exit (useful for scripting and testing)",
    )
    p.add_argument("--verbose", "-v", action="store_true", help="Enable DEBUG logging")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    log.setLevel(logging.DEBUG if args.verbose else logging.INFO)
    try:
        run_watchdog(args)
    except KeyboardInterrupt:
        log.info("Watchdog stopped")
        sys.exit(0)
```
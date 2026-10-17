#!/usr/bin/env python3
"""
009_alarm_handlers.py — NSO Alarm Correlation and Auto-Remediation

Polls the NSO alarm manager via RESTCONF, correlates active alarms by
device and alarm type, and dispatches configurable remediation actions
(log, clear, or re-sync device) based on severity thresholds.

Usage:
    python3 009_alarm_handlers.py --host 127.0.0.1 --user admin --password admin
    python3 009_alarm_handlers.py --host 127.0.0.1 --user admin --password admin \
        --severity critical --action resync --loop 60

Prerequisites:
    - NSO (Network Services Orchestrator) with RESTCONF enabled (port 8080 default)
    - NSO user with alarm-read and device RPC permissions
    - stdlib only: urllib, base64, json, logging, argparse, time
    - Python 3.10+

NSO alarm severities in ascending order:
    indeterminate < warning < minor < major < critical
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
from typing import Optional

SEVERITY_ORDER = ["indeterminate", "warning", "minor", "major", "critical"]

LOG = logging.getLogger(__name__)


@dataclass
class Alarm:
    device: str
    alarm_type: str
    severity: str
    text: str
    time_created: str
    is_cleared: bool = False
    managed_object: str = ""

    @property
    def severity_level(self) -> int:
        try:
            return SEVERITY_ORDER.index(self.severity)
        except ValueError:
            return 0


@dataclass
class AlarmCorrelator:
    """Deduplicates alarms so each (device, type) pair triggers once per lifecycle."""

    threshold_severity: str = "major"
    seen: dict = field(default_factory=dict)

    def ingest(self, alarms: list[Alarm]) -> list[Alarm]:
        threshold = SEVERITY_ORDER.index(self.threshold_severity)
        triggered = []
        for alarm in alarms:
            key = (alarm.device, alarm.alarm_type)
            if alarm.is_cleared:
                self.seen.pop(key, None)
                continue
            if alarm.severity_level >= threshold and key not in self.seen:
                self.seen[key] = alarm
                triggered.append(alarm)
        return triggered


class NsoClient:
    def __init__(self, host: str, port: int, user: str, password: str, tls: bool = False):
        scheme = "https" if tls else "http"
        self.base_url = f"{scheme}://{host}:{port}/restconf"
        creds = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.headers = {
            "Authorization": f"Basic {creds}",
            "Accept": "application/yang-data+json",
            "Content-Type": "application/yang-data+json",
        }

    def _request(self, method: str, path: str, body: Optional[dict] = None) -> dict:
        url = self.base_url + path
        data = json.dumps(body).encode() if body else None
        req = urllib.request.Request(url, data=data, headers=self.headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            raise RuntimeError(
                f"HTTP {exc.code} on {method} {path}: {exc.read().decode()}"
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Connection error on {path}: {exc.reason}") from exc

    def get_alarms(self) -> list[Alarm]:
        data = self._request("GET", "/data/tailf-ncs-alarms:alarms/alarm-list/alarm")
        raw_list = data.get("tailf-ncs-alarms:alarm", [])
        alarms = []
        for raw in raw_list:
            mo = raw.get("managed-object", "")
            alarms.append(
                Alarm(
                    device=mo.split("/")[-1] or raw.get("device", "unknown"),
                    alarm_type=raw.get("type", "unknown"),
                    severity=raw.get("last-perceived-severity", "indeterminate"),
                    text=raw.get("last-alarm-text", ""),
                    time_created=raw.get("time-created", ""),
                    is_cleared=raw.get("is-cleared", False),
                    managed_object=mo,
                )
            )
        return alarms

    def resync_device(self, device: str) -> bool:
        LOG.info("Triggering sync-from for device: %s", device)
        try:
            self._request(
                "POST",
                f"/data/tailf-ncs:devices/device={device}/sync-from",
                {},
            )
            return True
        except RuntimeError as exc:
            LOG.warning("sync-from failed for %s: %s", device, exc)
            return False

    def clear_alarm(self, device: str, alarm_type: str) -> bool:
        LOG.info("Clearing alarm %s on %s", alarm_type, device)
        body = {"input": {"device": device, "type": alarm_type}}
        try:
            self._request(
                "POST", "/data/tailf-ncs-alarms:alarms/clear-alarm", body
            )
            return True
        except RuntimeError as exc:
            LOG.warning("clear-alarm failed: %s", exc)
            return False


def handle_alarm(client: NsoClient, alarm: Alarm, action: str) -> None:
    LOG.warning(
        "ALARM [%s] device=%s type=%s text=%s",
        alarm.severity.upper(),
        alarm.device,
        alarm.alarm_type,
        alarm.text,
    )
    if action == "resync":
        client.resync_device(alarm.device)
    elif action == "clear":
        client.clear_alarm(alarm.device, alarm.alarm_type)


def run_once(client: NsoClient, correlator: AlarmCorrelator, action: str) -> int:
    try:
        alarms = client.get_alarms()
    except RuntimeError as exc:
        LOG.error("Failed to fetch alarms: %s", exc)
        return 1
    triggered = correlator.ingest(alarms)
    LOG.info(
        "Fetched %d alarm(s); %d new at or above threshold '%s'",
        len(alarms),
        len(triggered),
        correlator.threshold_severity,
    )
    for alarm in triggered:
        handle_alarm(client, alarm, action)
    return 0


def build_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="NSO alarm correlation and auto-remediation handler",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--host", default="127.0.0.1", help="NSO host")
    parser.add_argument("--port", type=int, default=8080, help="NSO RESTCONF port")
    parser.add_argument("--user", default="admin", help="NSO username")
    parser.add_argument("--password", default="admin", help="NSO password")
    parser.add_argument("--tls", action="store_true", help="Use HTTPS")
    parser.add_argument(
        "--severity",
        choices=SEVERITY_ORDER,
        default="major",
        help="Minimum alarm severity to act on",
    )
    parser.add_argument(
        "--action",
        choices=["log", "clear", "resync"],
        default="log",
        help="Remediation: log only, clear alarm, or sync-from device",
    )
    parser.add_argument(
        "--loop",
        type=int,
        default=0,
        metavar="SECONDS",
        help="Poll interval in seconds; 0 = run once and exit",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


if __name__ == "__main__":
    args = build_args()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    nso = NsoClient(args.host, args.port, args.user, args.password, args.tls)
    correlator = AlarmCorrelator(threshold_severity=args.severity)
    if args.loop > 0:
        LOG.info(
            "Starting poll loop every %ds (severity>=%s action=%s)",
            args.loop,
            args.severity,
            args.action,
        )
        while True:
            run_once(nso, correlator, args.action)
            time.sleep(args.loop)
    else:
        sys.exit(run_once(nso, correlator, args.action))
The user wants only the script content output. Here it is:

#!/usr/bin/env python3
"""
028_cdb_operations.py — NSO CDB Commit Queue Monitor and Recovery Tool

Purpose:
    Monitors the NSO Configuration Database (CDB) commit queue, identifies
    stuck or failed commit-queue items, and provides targeted recovery
    operations.  In production NSO environments, a stalled commit queue
    causes configuration drift between the CDB and managed devices without
    raising an obvious alarm.

Usage:
    python3 028_cdb_operations.py --host <nso> --user <user> --password <pw> \\
        [--port PORT] [--tls] [--action list|inspect|clear] [--item-id ID]

Prerequisites:
    - NSO 5.x+ with RESTCONF API enabled (ncs.conf restconf section)
    - NSO account with 'admin' or 'oper' NACM privilege
    - Network path to NSO RESTCONF port (default 8080 / 8888 TLS)
    - Python 3.9+, stdlib only (urllib, json, logging, argparse)

Examples:
    # Show all active and recently completed commit-queue entries
    python3 028_cdb_operations.py --host 10.0.0.1 --user admin --password Admin1!

    # Dump full detail for a stuck item
    python3 028_cdb_operations.py --host 10.0.0.1 --user admin --password Admin1! \\
        --action inspect --item-id 1718200000000

    # Remove a permanently failed item from the completed queue
    python3 028_cdb_operations.py --host 10.0.0.1 --user admin --password Admin1! \\
        --action clear --item-id 1718200000000
"""

import argparse
import base64
import json
import logging
import sys
import urllib.error
import urllib.request
from typing import Any, Optional

logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

_COMMIT_QUEUE = "/data/tailf-ncs:devices/commit-queue"
_COMPLETED = "/data/tailf-ncs:devices/commit-queue/completed/queue-item"


class NSORestconf:
    def __init__(
        self, host: str, port: int, username: str, password: str, tls: bool = False
    ) -> None:
        scheme = "https" if tls else "http"
        self._base = f"{scheme}://{host}:{port}/restconf"
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        self._headers = {
            "Authorization": f"Basic {token}",
            "Accept": "application/yang-data+json",
            "Content-Type": "application/yang-data+json",
        }

    def _call(self, method: str, path: str, body: Optional[dict] = None) -> dict:
        url = self._base + path
        payload = json.dumps(body).encode() if body else None
        req = urllib.request.Request(url, data=payload, headers=self._headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            log.error("HTTP %d %s — %s", exc.code, path, detail[:200])
            raise
        except urllib.error.URLError as exc:
            log.error("Connection error reaching %s: %s", url, exc.reason)
            raise

    def get(self, path: str) -> dict:
        return self._call("GET", path)

    def delete(self, path: str) -> None:
        self._call("DELETE", path)


def _fmt_item(item: dict[str, Any]) -> None:
    item_id = item.get("id", "?")
    status = item.get("status", "unknown")
    age = item.get("age", "N/A")
    devices = [d.get("name", "?") for d in item.get("devices", {}).get("device", [])]
    print(f"  id      : {item_id}")
    print(f"  status  : {status}")
    print(f"  age     : {age}s")
    print(f"  devices : {', '.join(devices) or '—'}")
    err = item.get("error-info", item.get("error"))
    if err:
        print(f"  error   : {err}")
    print()


def cmd_list(client: NSORestconf) -> None:
    log.info("Querying NSO CDB commit queue …")
    data = client.get(_COMMIT_QUEUE).get("tailf-ncs:commit-queue", {})

    active = data.get("queue", {}).get("queue-item", [])
    completed = data.get("completed", {}).get("queue-item", [])

    if not active and not completed:
        log.info("Commit queue is empty — nothing pending or completed.")
        return

    if active:
        print(f"\n{'─'*56}")
        print(f"  ACTIVE ({len(active)} item{'s' if len(active) != 1 else ''})")
        print(f"{'─'*56}")
        for item in active:
            _fmt_item(item)

    if completed:
        print(f"\n{'─'*56}")
        print(f"  COMPLETED / FAILED ({len(completed)} item{'s' if len(completed) != 1 else ''})")
        print(f"{'─'*56}")
        for item in completed:
            _fmt_item(item)


def cmd_inspect(client: NSORestconf, item_id: str) -> None:
    path = f"{_COMPLETED}={item_id}"
    log.info("Fetching detail for commit-queue item %s …", item_id)
    try:
        result = client.get(path)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            log.error("Item %s not found in the completed queue.", item_id)
        sys.exit(1)

    item = result.get("tailf-ncs:queue-item", result)
    print(json.dumps(item, indent=2))


def cmd_clear(client: NSORestconf, item_id: str) -> None:
    path = f"{_COMPLETED}={item_id}"
    log.info("Clearing commit-queue item %s …", item_id)
    try:
        client.delete(path)
        log.info("Item %s removed from completed queue.", item_id)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            log.error("Item %s not found; already cleared?", item_id)
        sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="NSO CDB commit-queue monitor and recovery tool.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--host", required=True, help="NSO hostname or IP")
    p.add_argument("--port", type=int, default=8080, help="NSO RESTCONF port")
    p.add_argument("--user", required=True, help="NSO username")
    p.add_argument("--password", required=True, help="NSO password")
    p.add_argument("--tls", action="store_true", help="Use HTTPS")
    p.add_argument(
        "--action",
        choices=["list", "inspect", "clear"],
        default="list",
        help="list: show queue; inspect: dump item JSON; clear: delete failed item",
    )
    p.add_argument(
        "--item-id",
        metavar="ID",
        help="Commit-queue item ID (required for inspect and clear)",
    )
    p.add_argument("--debug", action="store_true", help="Enable DEBUG logging")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.action in ("inspect", "clear") and not args.item_id:
        log.error("--item-id is required for action '%s'", args.action)
        sys.exit(1)

    client = NSORestconf(
        host=args.host,
        port=args.port,
        username=args.user,
        password=args.password,
        tls=args.tls,
    )

    try:
        if args.action == "list":
            cmd_list(client)
        elif args.action == "inspect":
            cmd_inspect(client, args.item_id)
        elif args.action == "clear":
            cmd_clear(client, args.item_id)
    except (urllib.error.HTTPError, urllib.error.URLError):
        sys.exit(1)
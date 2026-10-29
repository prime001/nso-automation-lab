NSO CDB Rollback Inspector and Manager

Purpose:
    Inspect, compare, and selectively apply NSO configuration rollback files
    stored in the Configuration Database (CDB). Useful for auditing change
    history, pinpointing when a misconfiguration was introduced, and safely
    reverting targeted rollbacks without a full factory reset.

Usage:
    python 018_cdb_operations.py list --host 10.0.0.1 --user admin --password admin
    python 018_cdb_operations.py show  --host 10.0.0.1 --id 0
    python 018_cdb_operations.py diff  --host 10.0.0.1 --id 0 --compare 1
    python 018_cdb_operations.py apply --host 10.0.0.1 --id 2 [--dry-run]
    python 018_cdb_operations.py export --host 10.0.0.1 --id 0 --output /tmp/rb0.cfg

Prerequisites:
    - NSO >= 5.x with RESTCONF enabled (ncs.conf: restconf/enabled true)
    - rollback-numbering enabled in ncs.conf (default in modern NSO)
    - NSO user with the 'read' NACM privilege on tailf-rollback; 'write' for apply
    - Python 3.8+, stdlib only (urllib, json, difflib, argparse, logging)
"""

import argparse
import base64
import difflib
import json
import logging
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

_ROLLBACK_BASE = "/restconf/data/tailf-rollback:rollback-files"
_ROLLBACK_APPLY = "/restconf/operations/tailf-rollback:apply-rollback-file"


def _auth_header(user: str, password: str) -> str:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return f"Basic {token}"


def _get(base_url: str, path: str, auth: str) -> dict:
    req = urllib.request.Request(
        f"{base_url}{path}",
        headers={"Authorization": auth, "Accept": "application/yang-data+json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"GET {path} failed {exc.code}: {exc.read().decode()}") from exc


def _post(base_url: str, path: str, auth: str, payload: dict) -> Optional[dict]:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{base_url}{path}",
        data=body,
        headers={
            "Authorization": auth,
            "Accept": "application/yang-data+json",
            "Content-Type": "application/yang-data+json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode()
            return json.loads(raw) if raw.strip() else None
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"POST {path} failed {exc.code}: {exc.read().decode()}") from exc


def fetch_list(base_url: str, auth: str) -> list:
    data = _get(base_url, _ROLLBACK_BASE, auth)
    return data.get("tailf-rollback:rollback-files", {}).get("file", [])


def fetch_content(base_url: str, auth: str, rollback_id: int) -> str:
    path = f"{_ROLLBACK_BASE}/file={rollback_id}/content"
    data = _get(base_url, path, auth)
    return data.get("tailf-rollback:content", "")


def cmd_list(args, base_url: str, auth: str) -> int:
    files = fetch_list(base_url, auth)
    if not files:
        log.info("No rollback files found in CDB.")
        return 0
    print(f"{'ID':>4}  {'Timestamp':<22}  {'Creator':<20}  Label")
    print("-" * 74)
    for f in files:
        print(
            f"{f.get('id', '?'):>4}  "
            f"{f.get('date-time', 'unknown'):<22}  "
            f"{f.get('creator', 'unknown'):<20}  "
            f"{f.get('label', '')}"
        )
    log.info("Total: %d rollback file(s).", len(files))
    return 0


def cmd_show(args, base_url: str, auth: str) -> int:
    content = fetch_content(base_url, auth, args.id)
    if not content:
        log.warning("Rollback %d returned empty content.", args.id)
        return 1
    print(content)
    return 0


def cmd_diff(args, base_url: str, auth: str) -> int:
    log.info("Fetching rollback %d...", args.id)
    a = fetch_content(base_url, auth, args.id).splitlines(keepends=True)
    log.info("Fetching rollback %d...", args.compare)
    b = fetch_content(base_url, auth, args.compare).splitlines(keepends=True)
    delta = list(
        difflib.unified_diff(a, b, fromfile=f"rollback-{args.id}", tofile=f"rollback-{args.compare}")
    )
    if not delta:
        print(f"Rollbacks {args.id} and {args.compare} are identical.")
    else:
        print("".join(delta))
    return 0


def cmd_apply(args, base_url: str, auth: str) -> int:
    payload: dict = {"tailf-rollback:input": {"id": args.id, "path": "/"}}
    if args.dry_run:
        payload["tailf-rollback:input"]["dry-run"] = {}
    mode = "Dry-run applying" if args.dry_run else "Applying"
    log.info("%s rollback %d...", mode, args.id)
    result = _post(base_url, _ROLLBACK_APPLY, auth, payload) or {}
    output = result.get("tailf-rollback:output", result)
    if output:
        print(json.dumps(output, indent=2))
    log.info(
        "Done. %s",
        "No changes committed (dry-run)." if args.dry_run else f"Rollback {args.id} applied.",
    )
    return 0


def cmd_export(args, base_url: str, auth: str) -> int:
    content = fetch_content(base_url, auth, args.id)
    if not content:
        log.error("Rollback %d returned empty content; nothing exported.", args.id)
        return 1
    dest = Path(args.output)
    dest.write_text(content, encoding="utf-8")
    log.info("Rollback %d written to %s (%d bytes).", args.id, dest, len(content))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Inspect and manage NSO CDB rollback files via RESTCONF.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--host", default="localhost", help="NSO host or IP")
    p.add_argument("--port", type=int, default=8080, help="RESTCONF port")
    p.add_argument("--user", default="admin", help="NSO username")
    p.add_argument("--password", default="admin", help="NSO password")
    p.add_argument("--tls", action="store_true", help="Use HTTPS")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")

    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="List rollback files with metadata")

    sp = sub.add_parser("show", help="Print full content of a rollback file")
    sp.add_argument("--id", type=int, required=True, help="Rollback ID")

    dp = sub.add_parser("diff", help="Unified diff between two rollback files")
    dp.add_argument("--id", type=int, required=True, help="Base rollback ID")
    dp.add_argument("--compare", type=int, required=True, help="Rollback to compare against")

    ap = sub.add_parser("apply", help="Apply a rollback to restore configuration")
    ap.add_argument("--id", type=int, required=True, help="Rollback ID to apply")
    ap.add_argument("--dry-run", action="store_true", help="Simulate without committing")

    ep = sub.add_parser("export", help="Write rollback content to a local file")
    ep.add_argument("--id", type=int, required=True, help="Rollback ID")
    ep.add_argument("--output", required=True, help="Destination file path")

    return p


_COMMANDS = {
    "list": cmd_list,
    "show": cmd_show,
    "diff": cmd_diff,
    "apply": cmd_apply,
    "export": cmd_export,
}

if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    scheme = "https" if args.tls else "http"
    base_url = f"{scheme}://{args.host}:{args.port}"
    auth = _auth_header(args.user, args.password)

    try:
        sys.exit(_COMMANDS[args.command](args, base_url, auth))
    except RuntimeError as exc:
        log.error("%s", exc)
        sys.exit(1)
    except KeyboardInterrupt:
        log.info("Interrupted.")
        sys.exit(130)
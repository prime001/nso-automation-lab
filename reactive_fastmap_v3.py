022_reactive_fastmap.py — NSO RESTCONF Service State Reactive Fastmap

Purpose:
    Polls NSO via RESTCONF for service sync-state transitions and automatically
    triggers re-deploy when a service drifts out of sync.  Includes per-service
    remediation caps and exponential backoff so a persistently broken device does
    not loop indefinitely and burn change windows.

Usage:
    python 022_reactive_fastmap.py --host 127.0.0.1 --user admin --password admin
    python 022_reactive_fastmap.py --host nso.lab --service-type l3vpn --interval 30
    python 022_reactive_fastmap.py --host nso.lab --dry-run --verbose

Prerequisites:
    - NSO 5.x+ with RESTCONF enabled (default port 8080, or 8443 with --tls)
    - Service packages deployed with commit-queue / deviation-tracking enabled
    - pip install requests
"""

import argparse
import logging
import sys
import time
from collections import defaultdict
from typing import Dict, Optional

import requests
from requests.auth import HTTPBasicAuth

log = logging.getLogger(__name__)

SYNC_REMEDIATE = {"out-of-sync", "error"}
BACKOFF_BASE = 10


def build_session(user: str, password: str, verify_ssl: bool) -> requests.Session:
    session = requests.Session()
    session.auth = HTTPBasicAuth(user, password)
    session.headers.update({"Accept": "application/yang-data+json",
                             "Content-Type": "application/yang-data+json"})
    session.verify = verify_ssl
    return session


def fetch_services(session: requests.Session, base_url: str, svc_type: str) -> Dict[str, dict]:
    url = f"{base_url}/restconf/data/tailf-ncs:services/{svc_type}"
    try:
        resp = session.get(url, timeout=10)
        if resp.status_code == 404:
            log.warning("Service type '%s' not found on NSO; check package name.", svc_type)
            return {}
        resp.raise_for_status()
        data = resp.json()
        items = data.get(svc_type, [])
        if isinstance(items, dict):
            items = [items]
        return {svc.get("name", str(i)): svc for i, svc in enumerate(items)}
    except requests.RequestException as exc:
        log.error("fetch_services error: %s", exc)
        return {}


def check_sync(session: requests.Session, base_url: str, svc_type: str, name: str) -> Optional[str]:
    url = f"{base_url}/restconf/data/tailf-ncs:services/{svc_type}={name}/check-sync"
    try:
        resp = session.post(url, timeout=15)
        resp.raise_for_status()
        return resp.json().get("tailf-ncs:output", {}).get("result", "unknown")
    except requests.RequestException as exc:
        log.debug("check-sync failed for %s/%s: %s", svc_type, name, exc)
        return "unknown"


def redeploy(session: requests.Session, base_url: str, svc_type: str, name: str, dry_run: bool) -> bool:
    if dry_run:
        log.info("[DRY-RUN] re-deploy %s/%s", svc_type, name)
        return True
    url = f"{base_url}/restconf/data/tailf-ncs:services/{svc_type}={name}/re-deploy"
    try:
        resp = session.post(url, json={}, timeout=30)
        resp.raise_for_status()
        log.info("re-deploy triggered: %s/%s", svc_type, name)
        return True
    except requests.RequestException as exc:
        log.error("re-deploy failed for %s/%s: %s", svc_type, name, exc)
        return False


def run_loop(args: argparse.Namespace) -> None:
    scheme = "https" if args.tls else "http"
    base_url = f"{scheme}://{args.host}:{args.port}"
    session = build_session(args.user, args.password, verify_ssl=args.tls and not args.no_verify)

    prev_states: Dict[str, str] = {}
    remediation_counts: Dict[str, int] = defaultdict(int)
    backoff_until: Dict[str, float] = {}

    log.info("Reactive fastmap started — host=%s svc_type=%s interval=%ds max_remediations=%d",
             args.host, args.service_type, args.interval, args.max_remediations)

    while True:
        services = fetch_services(session, base_url, args.service_type)

        for name in services:
            now = time.monotonic()
            if backoff_until.get(name, 0) > now:
                remaining = backoff_until[name] - now
                log.debug("Skipping %s (backoff %.0fs remaining)", name, remaining)
                continue

            state = check_sync(session, base_url, args.service_type, name)
            prev = prev_states.get(name)

            if state != prev:
                log.info("State change — %s/%s: %s → %s",
                         args.service_type, name, prev or "(new)", state)

            if state in SYNC_REMEDIATE:
                count = remediation_counts[name]
                if count >= args.max_remediations:
                    log.warning("Service %s/%s hit remediation cap (%d); manual intervention required.",
                                name, args.max_remediations, name)
                else:
                    if redeploy(session, base_url, args.service_type, name, args.dry_run):
                        remediation_counts[name] += 1
                        delay = BACKOFF_BASE * (2 ** count)
                        backoff_until[name] = now + delay
                        log.info("Backoff %ds applied to %s (attempt %d/%d)",
                                 delay, name, remediation_counts[name], args.max_remediations)

            elif state == "in-sync" and name in remediation_counts:
                log.info("Recovered: %s/%s — resetting counters.", args.service_type, name)
                remediation_counts.pop(name, None)
                backoff_until.pop(name, None)

            prev_states[name] = state

        removed = set(prev_states) - set(services)
        for name in removed:
            log.info("Service removed from NSO: %s/%s", args.service_type, name)
            prev_states.pop(name, None)
            remediation_counts.pop(name, None)
            backoff_until.pop(name, None)

        log.debug("Poll complete (%d services). Sleeping %ds.", len(services), args.interval)
        time.sleep(args.interval)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Reactive fastmap: watches NSO service sync-state and auto-remediates drift."
    )
    p.add_argument("--host", required=True, help="NSO hostname or IP address")
    p.add_argument("--port", type=int, default=8080, help="RESTCONF port (default: 8080)")
    p.add_argument("--user", default="admin", help="NSO username")
    p.add_argument("--password", default="admin", help="NSO password")
    p.add_argument("--tls", action="store_true", help="Use HTTPS")
    p.add_argument("--no-verify", action="store_true", help="Disable TLS certificate verification")
    p.add_argument("--service-type", default="l3vpn", metavar="TYPE",
                   help="NSO service list name to watch (default: l3vpn)")
    p.add_argument("--interval", type=int, default=15, metavar="SECS",
                   help="Poll interval in seconds (default: 15)")
    p.add_argument("--max-remediations", type=int, default=3, metavar="N",
                   help="Max re-deploy attempts per service before backing off permanently (default: 3)")
    p.add_argument("--dry-run", action="store_true",
                   help="Log planned actions without executing them")
    p.add_argument("--verbose", "-v", action="store_true", help="Enable DEBUG logging")
    return p.parse_args()


if __name__ == "__main__":
    _args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if _args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stdout,
    )
    try:
        run_loop(_args)
    except KeyboardInterrupt:
        log.info("Interrupted by operator. Exiting cleanly.")
        sys.exit(0)
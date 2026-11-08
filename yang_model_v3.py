```python
"""
025_yang_restconf_explorer.py — RESTCONF YANG Capability and Data Explorer

Purpose:
    Queries a RESTCONF-capable network device (RFC 8040) to discover its
    supported YANG modules and retrieve operational or configuration data
    from arbitrary YANG paths. Useful for pre-service-deploy validation,
    compliance baselining, and auditing which YANG models a device exposes
    before targeting it with an NSO service package.

Usage:
    # List all implemented YANG modules
    python 025_yang_restconf_explorer.py \\
        --host 192.168.1.1 --user admin --password secret --capabilities

    # Fetch data from a specific YANG path
    python 025_yang_restconf_explorer.py \\
        --host 192.168.1.1 --user admin --password secret \\
        --path /data/ietf-interfaces:interfaces

    # Combine and save to file
    python 025_yang_restconf_explorer.py \\
        --host 192.168.1.1 --user admin --password secret \\
        --capabilities --path /data/Cisco-IOS-XE-native:native/hostname \\
        --output baseline.json --show-imports

Prerequisites:
    - Device must support RESTCONF (RFC 8040) on HTTPS
    - Python 3.7+; stdlib only — no third-party dependencies
    - Read access credentials for the RESTCONF API
    - ietf-yang-library support for capability discovery
"""

import argparse
import json
import logging
import ssl
import sys
import urllib.error
import urllib.request
from base64 import b64encode
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)


def _auth_headers(username: str, password: str) -> Dict[str, str]:
    token = b64encode(f"{username}:{password}".encode()).decode()
    return {
        "Authorization": f"Basic {token}",
        "Accept": "application/yang-data+json",
    }


def _ssl_context(verify: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def restconf_get(
    host: str,
    path: str,
    username: str,
    password: str,
    port: int = 443,
    verify_ssl: bool = False,
    timeout: int = 15,
) -> Optional[Dict[str, Any]]:
    if not path.startswith("/"):
        path = "/" + path
    url = f"https://{host}:{port}/restconf{path}"
    req = urllib.request.Request(url, headers=_auth_headers(username, password))
    log.debug("GET %s", url)
    try:
        with urllib.request.urlopen(req, context=_ssl_context(verify_ssl), timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body) if body.strip() else {}
    except urllib.error.HTTPError as exc:
        body_snippet = exc.read().decode("utf-8", errors="replace")[:200]
        log.error("HTTP %d %s — %s", exc.code, exc.reason, body_snippet)
        if exc.code == 401:
            log.error("Authentication failed — check --user / --password")
        elif exc.code == 404:
            log.error("Path not found — verify YANG module name and path")
        return None
    except urllib.error.URLError as exc:
        log.error("Connection error to %s:%d — %s", host, port, exc.reason)
        return None
    except json.JSONDecodeError as exc:
        log.error("Malformed JSON in response: %s", exc)
        return None


def fetch_yang_modules(
    host: str, username: str, password: str, port: int, verify_ssl: bool
) -> List[Dict[str, str]]:
    data = restconf_get(
        host, "/data/ietf-yang-library:modules-state",
        username, password, port, verify_ssl,
    )
    if data is None:
        return []
    modules = (
        data.get("ietf-yang-library:modules-state", {}).get("module", [])
    )
    log.info("Discovered %d YANG modules on %s", len(modules), host)
    return modules


def print_module_table(modules: List[Dict[str, str]], show_imports: bool) -> None:
    if not modules:
        print("No YANG modules returned.")
        return

    implemented = sorted(
        [m for m in modules if m.get("conformance-type") == "implement"],
        key=lambda m: m.get("name", ""),
    )
    imported = sorted(
        [m for m in modules if m.get("conformance-type") == "import"],
        key=lambda m: m.get("name", ""),
    )

    rows = implemented + (imported if show_imports else [])
    width = 70
    print(f"\n{'=' * width}")
    print(f"{'MODULE':<44} {'REVISION':<12} CONFORMANCE")
    print(f"{'=' * width}")
    for m in rows:
        name = m.get("name", "unknown")[:43]
        rev = m.get("revision") or "—"
        ctype = m.get("conformance-type", "unknown")
        print(f"{name:<44} {rev:<12} {ctype}")
    print(f"{'=' * width}")
    print(f"Implemented: {len(implemented)}   Imported: {len(imported)}")
    if not show_imports and imported:
        print(f"(pass --show-imports to display {len(imported)} import-only modules)")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="RESTCONF YANG capability discovery and path data retrieval",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Requires a device with RESTCONF enabled (RFC 8040).",
    )
    p.add_argument("--host", required=True, help="Device hostname or IP address")
    p.add_argument("--user", required=True, help="RESTCONF username")
    p.add_argument("--password", required=True, help="RESTCONF password")
    p.add_argument("--port", type=int, default=443, help="HTTPS port (default: 443)")
    p.add_argument(
        "--capabilities", action="store_true",
        help="List supported YANG modules via ietf-yang-library",
    )
    p.add_argument(
        "--path",
        help="RESTCONF data path to fetch, e.g. /data/ietf-interfaces:interfaces",
    )
    p.add_argument(
        "--show-imports", action="store_true",
        help="Include import-only modules in capability table",
    )
    p.add_argument("--output", metavar="FILE", help="Write combined JSON result to file")
    p.add_argument("--no-verify-ssl", action="store_true", help="Skip TLS certificate verification")
    p.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    p.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%H:%M:%S",
    )

    if not args.capabilities and not args.path:
        log.error("Nothing to do — specify --capabilities, --path, or both")
        sys.exit(1)

    verify_ssl = not args.no_verify_ssl
    combined: Dict[str, Any] = {"host": args.host}
    exit_code = 0

    if args.capabilities:
        log.info("Fetching YANG module list from %s:%d", args.host, args.port)
        modules = fetch_yang_modules(args.host, args.user, args.password, args.port, verify_ssl)
        if not modules:
            log.error("Could not retrieve YANG capabilities")
            exit_code = 1
        else:
            print_module_table(modules, args.show_imports)
            combined["capabilities"] = modules

    if args.path:
        log.info("Fetching YANG path: %s", args.path)
        data = restconf_get(
            args.host, args.path, args.user, args.password,
            args.port, verify_ssl, args.timeout,
        )
        if data is None:
            log.error("Failed to retrieve data from path: %s", args.path)
            exit_code = 1
        else:
            print(json.dumps(data, indent=2))
            combined["path_data"] = data

    if args.output and len(combined) > 1:
        with open(args.output, "w") as fh:
            json.dump(combined, fh, indent=2)
        log.info("Result written to %s", args.output)

    sys.exit(exit_code)
```
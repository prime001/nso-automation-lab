```python
#!/usr/bin/env python3
"""
YANG Model Capability Discovery and Path Query Tool

Purpose:
    Connects to a RESTCONF-enabled device (Cisco NSO, IOS-XE, IOS-XR) and
    discovers supported YANG modules via the capabilities endpoint. Allows
    querying specific YANG data paths and extracting instance data.

Usage:
    python 035_yang_model.py --host 192.168.1.1 --user admin --path /interfaces
    python 035_yang_model.py --host 192.168.1.1 --user admin --list-modules
    python 035_yang_model.py --host 192.168.1.1 --user admin --path /system --output json

Prerequisites:
    - Device must have RESTCONF enabled (port 8080/443)
    - NSO: ncs.conf must enable RESTCONF
    - IOS-XE: `restconf` global config required
    - stdlib only (urllib, json, argparse, logging)
"""

import argparse
import base64
import json
import logging
import sys
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urljoin


logger = logging.getLogger(__name__)


def build_auth_header(username: str, password: str) -> str:
    creds = f"{username}:{password}"
    encoded = base64.b64encode(creds.encode()).decode()
    return f"Basic {encoded}"


def restconf_get(
    base_url: str,
    path: str,
    auth_header: str,
    timeout: int = 30,
    accept: str = "application/yang-data+json",
) -> dict[str, Any]:
    url = urljoin(base_url, path)
    req = urllib.request.Request(url)
    req.add_header("Authorization", auth_header)
    req.add_header("Accept", accept)
    req.add_header("Content-Type", "application/yang-data+json")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code} from {url}: {body[:200]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Connection failed to {url}: {exc.reason}") from exc


def fetch_capabilities(base_url: str, auth_header: str) -> list[dict]:
    logger.info("Fetching YANG capabilities from device")
    data = restconf_get(base_url, "/restconf/data/ietf-yang-library:modules-state", auth_header)
    modules = (
        data.get("ietf-yang-library:modules-state", {})
        .get("module", [])
    )
    return modules


def print_modules(modules: list[dict], filter_str: str | None = None) -> None:
    filtered = modules
    if filter_str:
        filtered = [m for m in modules if filter_str.lower() in m.get("name", "").lower()]

    print(f"\n{'Module Name':<50} {'Revision':<12} {'Conformance'}")
    print("-" * 80)
    for mod in sorted(filtered, key=lambda m: m.get("name", "")):
        name = mod.get("name", "unknown")
        revision = mod.get("revision", "n/a")
        conformance = mod.get("conformance-type", "n/a")
        print(f"{name:<50} {revision:<12} {conformance}")
    print(f"\nTotal: {len(filtered)} module(s)")


def query_path(
    base_url: str,
    auth_header: str,
    yang_path: str,
    output_format: str = "pretty",
) -> None:
    if not yang_path.startswith("/"):
        yang_path = "/" + yang_path

    restconf_path = f"/restconf/data{yang_path}"
    logger.info("Querying YANG path: %s", restconf_path)

    data = restconf_get(base_url, restconf_path, auth_header)

    if output_format == "json":
        print(json.dumps(data, indent=None))
    elif output_format == "compact":
        print(json.dumps(data))
    else:
        print(json.dumps(data, indent=2))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="YANG model capability discovery and RESTCONF path query tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--host", required=True, help="Device IP or hostname")
    parser.add_argument("--port", type=int, default=8080, help="RESTCONF port (default: 8080)")
    parser.add_argument("--user", required=True, help="Username")
    parser.add_argument("--password", default=None, help="Password (prompted if omitted)")
    parser.add_argument("--tls", action="store_true", help="Use HTTPS instead of HTTP")
    parser.add_argument(
        "--list-modules", action="store_true", help="List supported YANG modules"
    )
    parser.add_argument(
        "--filter", metavar="STRING", help="Filter module list by name substring"
    )
    parser.add_argument(
        "--path", metavar="YANG_PATH", help="YANG data path to query (e.g. /interfaces)"
    )
    parser.add_argument(
        "--output",
        choices=["pretty", "json", "compact"],
        default="pretty",
        help="Output format for path queries (default: pretty)",
    )
    parser.add_argument(
        "--timeout", type=int, default=30, help="Request timeout in seconds (default: 30)"
    )
    parser.add_argument(
        "--debug", action="store_true", help="Enable debug logging"
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    if not args.list_modules and not args.path:
        logger.error("Specify --list-modules or --path. Use --help for usage.")
        return 1

    password = args.password
    if password is None:
        import getpass
        password = getpass.getpass(f"Password for {args.user}@{args.host}: ")

    scheme = "https" if args.tls else "http"
    base_url = f"{scheme}://{args.host}:{args.port}"
    auth_header = build_auth_header(args.user, password)

    if args.tls:
        import ssl
        ssl._create_default_https_context = ssl._create_unverified_context

    try:
        if args.list_modules:
            modules = fetch_capabilities(base_url, auth_header)
            print_modules(modules, filter_str=args.filter)

        if args.path:
            query_path(base_url, auth_header, args.path, output_format=args.output)

    except RuntimeError as exc:
        logger.error("%s", exc)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
```
005_yang_model_validator.py — RESTCONF YANG Instance Validator

Purpose:
    Fetch a YANG model subtree from an NSO or RESTCONF-capable device via
    RFC 8040 RESTCONF, optionally validate leaf values against a JSON rules
    file, and report violations.  Useful for drift detection, audit pipelines,
    and CI gates that must assert specific model-level state before change windows.

Usage:
    python 005_yang_model_validator.py \
        --host 10.0.0.1 --port 8080 \
        --user admin --password secret \
        --path "Cisco-IOS-XE-native:native/interface/GigabitEthernet=1" \
        --rules rules.json \
        --output table

    rules.json example:
        {
          "Cisco-IOS-XE-native:GigabitEthernet": [
            {"leaf": "shutdown", "expect": false},
            {"leaf": "description", "contains": "PROD"},
            {"leaf": "mtu", "min": 1500, "max": 9216}
          ]
        }

Prerequisites:
    - Device or NSO northbound API must speak RESTCONF (RFC 8040).
    - Python 3.8+; no third-party packages required.
    - Credentials need at least read access to /restconf/data.
"""

from __future__ import annotations

import argparse
import json
import logging
import ssl
import sys
import urllib.error
import urllib.request
from base64 import b64encode
from typing import Any, Dict, List, Optional

LOG = logging.getLogger(__name__)


def build_url(host: str, port: int, path: str, scheme: str = "https") -> str:
    path = path.lstrip("/")
    return f"{scheme}://{host}:{port}/restconf/data/{path}"


def _install_no_verify_opener() -> None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    urllib.request.install_opener(opener)


def restconf_get(
    url: str, user: str, password: str, timeout: int = 15
) -> Dict[str, Any]:
    token = b64encode(f"{user}:{password}".encode()).decode()
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Basic {token}",
            "Accept": "application/yang-data+json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        LOG.error("HTTP %s from %s: %s — %s", exc.code, url, exc.reason, body[:200])
        raise
    except urllib.error.URLError as exc:
        LOG.error("Connection error fetching %s: %s", url, exc.reason)
        raise
    except json.JSONDecodeError as exc:
        LOG.error("Non-JSON response from %s at offset %d", url, exc.pos)
        raise


def load_rules(rules_path: str) -> Dict[str, List[Dict[str, Any]]]:
    try:
        with open(rules_path) as fh:
            data = json.load(fh)
    except OSError as exc:
        LOG.error("Cannot open rules file: %s", exc)
        raise
    except json.JSONDecodeError as exc:
        LOG.error("Invalid JSON in rules file: %s", exc)
        raise
    if not isinstance(data, dict):
        raise ValueError(f"Rules file must be a JSON object, got {type(data).__name__}")
    return data


def _check_leaf(container: str, rule: Dict[str, Any], entry: Dict[str, Any]) -> List[str]:
    violations: List[str] = []
    leaf = rule.get("leaf")
    if not leaf:
        return violations
    actual = entry.get(leaf)
    key = f"{container}.{leaf}"
    if "expect" in rule and actual != rule["expect"]:
        violations.append(f"{key}: expected {rule['expect']!r}, got {actual!r}")
    if "contains" in rule:
        if not isinstance(actual, str) or rule["contains"] not in actual:
            violations.append(f"{key}: expected to contain {rule['contains']!r}, got {actual!r}")
    if "min" in rule and actual is not None and actual < rule["min"]:
        violations.append(f"{key}: {actual} < minimum {rule['min']}")
    if "max" in rule and actual is not None and actual > rule["max"]:
        violations.append(f"{key}: {actual} > maximum {rule['max']}")
    return violations


def validate(
    data: Dict[str, Any], rules: Dict[str, List[Dict[str, Any]]]
) -> List[str]:
    violations: List[str] = []
    for container_key, rule_list in rules.items():
        subtree = data.get(container_key)
        if subtree is None:
            violations.append(f"{container_key}: key not present in response")
            continue
        entries = subtree if isinstance(subtree, list) else [subtree]
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            for rule in rule_list:
                violations.extend(_check_leaf(container_key, rule, entry))
    return violations


def emit_table(data: Dict[str, Any], violations: List[str]) -> None:
    print("\n=== YANG Data ===")
    print(json.dumps(data, indent=2))
    print(f"\n=== Validation ({len(violations)} violation(s)) ===")
    if violations:
        for v in violations:
            print(f"  FAIL  {v}")
    else:
        print("  PASS  All rules satisfied.")


def emit_json(data: Dict[str, Any], violations: List[str]) -> None:
    print(json.dumps({"data": data, "violations": violations, "passed": not violations}, indent=2))


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Fetch and validate a RESTCONF YANG subtree.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--host", required=True, help="Device hostname or IP")
    p.add_argument("--port", type=int, default=443, help="RESTCONF port")
    p.add_argument("--user", required=True, help="Username")
    p.add_argument("--password", required=True, help="Password")
    p.add_argument(
        "--path",
        required=True,
        help="YANG data path under /restconf/data/, e.g. Cisco-IOS-XE-native:native/interface",
    )
    p.add_argument("--scheme", choices=["http", "https"], default="https", help="URL scheme")
    p.add_argument("--rules", metavar="FILE", help="JSON validation rules file (optional)")
    p.add_argument("--output", choices=["table", "json"], default="table", help="Output format")
    p.add_argument("--timeout", type=int, default=15, help="HTTP timeout in seconds")
    p.add_argument("--no-verify-ssl", action="store_true", help="Disable TLS certificate verification")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s  %(levelname)-7s  %(message)s",
    )

    if args.no_verify_ssl:
        LOG.warning("TLS verification disabled — do not use in production")
        _install_no_verify_opener()

    url = build_url(args.host, args.port, args.path, args.scheme)
    LOG.info("Fetching %s", url)

    try:
        data = restconf_get(url, args.user, args.password, args.timeout)
    except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError):
        return 1

    rules: Dict[str, List[Dict[str, Any]]] = {}
    if args.rules:
        try:
            rules = load_rules(args.rules)
        except (OSError, json.JSONDecodeError, ValueError):
            return 1

    violations = validate(data, rules) if rules else []

    if args.output == "json":
        emit_json(data, violations)
    else:
        emit_table(data, violations)

    if violations:
        LOG.warning("%d validation violation(s) found", len(violations))
        return 1

    LOG.info("Validation passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
The user's request is fully specified with explicit output instructions ("Output ONLY the script content"). Their instructions take precedence over the brainstorming process. Writing the script now.

```python
#!/usr/bin/env python3
"""
027_config_drift.py — NSO Config Drift Detector

Compares the intended device configuration stored in NSO's CDB (via RESTCONF)
against the actual running configuration collected directly from the device via
SSH. Produces a per-device drift report highlighting configuration lines that
exist in one source but not the other.

Usage:
    python 027_config_drift.py \\
        --nso-host 192.168.1.10 \\
        --device router-core-01 \\
        --username admin \\
        [--password secret] \\
        [--device-host 10.0.0.1] \\
        [--output drift-report.json]

Prerequisites:
    - NSO instance with RESTCONF enabled (default port 8080)
    - pip install paramiko
    - Read-only CLI access on managed devices
    - Network reachability between this host and both NSO and the target device
"""

import argparse
import base64
import difflib
import getpass
import json
import logging
import sys
import urllib.error
import urllib.request
from typing import Optional

try:
    import paramiko
except ImportError:
    print("ERROR: paramiko required — pip install paramiko", file=sys.stderr)
    sys.exit(1)

LOG = logging.getLogger(__name__)


def fetch_nso_config(
    nso_host: str,
    device: str,
    username: str,
    password: str,
    port: int = 8080,
) -> Optional[str]:
    """Pull intended device config from NSO CDB via RESTCONF."""
    url = (
        f"http://{nso_host}:{port}/restconf/data/"
        f"tailf-ncs:devices/device={device}/config"
    )
    creds = base64.b64encode(f"{username}:{password}".encode()).decode()
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/yang-data+json",
            "Authorization": f"Basic {creds}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read().decode())
            return json.dumps(body, indent=2)
    except urllib.error.HTTPError as exc:
        LOG.error("NSO RESTCONF %s HTTP %s: %s", url, exc.code, exc.reason)
        return None
    except urllib.error.URLError as exc:
        LOG.error("Cannot reach NSO at %s:%s — %s", nso_host, port, exc.reason)
        return None


def fetch_device_config(
    host: str,
    username: str,
    password: str,
    port: int = 22,
) -> Optional[str]:
    """Collect running configuration from device via SSH."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            port=port,
            username=username,
            password=password,
            timeout=15,
            look_for_keys=False,
            allow_agent=False,
        )
        _, stdout, stderr = client.exec_command("show running-config", timeout=30)
        output = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace").strip()
        if err:
            LOG.warning("SSH stderr from %s: %s", host, err)
        return output
    except paramiko.AuthenticationException:
        LOG.error("Authentication failed for %s@%s", username, host)
        return None
    except paramiko.SSHException as exc:
        LOG.error("SSH error on %s: %s", host, exc)
        return None
    except OSError as exc:
        LOG.error("Cannot connect to %s:%s — %s", host, port, exc)
        return None
    finally:
        client.close()


def compute_drift(intended: str, actual: str, device: str) -> dict:
    """Diff intended vs actual config and return a structured report."""
    intended_lines = intended.splitlines(keepends=True)
    actual_lines = actual.splitlines(keepends=True)
    diff = list(
        difflib.unified_diff(
            intended_lines,
            actual_lines,
            fromfile=f"{device}/nso-intended",
            tofile=f"{device}/device-running",
            lineterm="",
        )
    )
    missing = [ln.lstrip("-").rstrip() for ln in diff if ln.startswith("- ")]
    extra = [ln.lstrip("+").rstrip() for ln in diff if ln.startswith("+ ")]
    return {
        "device": device,
        "in_sync": len(diff) == 0,
        "lines_missing_from_device": missing,
        "lines_extra_on_device": extra,
        "drift_line_count": len(missing) + len(extra),
        "unified_diff": "".join(diff),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Detect config drift between NSO CDB intent and device running-config.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--nso-host", required=True, help="NSO server hostname or IP")
    parser.add_argument("--nso-port", type=int, default=8080, help="NSO RESTCONF port")
    parser.add_argument("--device", required=True, help="NSO managed device name")
    parser.add_argument(
        "--device-host",
        help="Device SSH hostname/IP (defaults to --device value)",
    )
    parser.add_argument("--device-port", type=int, default=22, help="Device SSH port")
    parser.add_argument("--username", required=True, help="Username for NSO and device")
    parser.add_argument("--password", help="Password (prompted if omitted)")
    parser.add_argument("--output", metavar="FILE", help="Write JSON report to file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    password = args.password or getpass.getpass(f"Password for {args.username}: ")
    device_host = args.device_host or args.device

    LOG.info("Fetching intended config from NSO for '%s'", args.device)
    intended = fetch_nso_config(
        args.nso_host, args.device, args.username, password, port=args.nso_port
    )
    if intended is None:
        LOG.error("Could not retrieve intended config from NSO — aborting.")
        return 1

    LOG.info("Fetching running config from device '%s' (%s)", args.device, device_host)
    actual = fetch_device_config(
        device_host, args.username, password, port=args.device_port
    )
    if actual is None:
        LOG.error("Could not retrieve running config from device — aborting.")
        return 1

    report = compute_drift(intended, actual, args.device)

    if report["in_sync"]:
        LOG.info("'%s' is IN SYNC with NSO intent.", args.device)
    else:
        LOG.warning(
            "'%s' has DRIFT — %d line(s) missing, %d line(s) extra.",
            args.device,
            len(report["lines_missing_from_device"]),
            len(report["lines_extra_on_device"]),
        )

    payload = json.dumps(report, indent=2)
    if args.output:
        with open(args.output, "w") as fh:
            fh.write(payload)
        LOG.info("Report written to %s", args.output)
    else:
        print(payload)

    return 0 if report["in_sync"] else 2


if __name__ == "__main__":
    sys.exit(main())
```
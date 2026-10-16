```python
"""
007_config_baseline_diff.py — Configuration Baseline Drift Detector

Purpose:
    Connects to network devices via SSH, retrieves the running configuration,
    and compares it against a stored golden baseline.  Any deviation is
    reported as a unified diff so operators can quickly identify unexpected
    changes before they cause outages.

Usage:
    # Check a single device against its stored baseline
    python 007_config_baseline_diff.py -d 192.168.1.1 -u admin -p secret

    # Save current running config as the new golden baseline
    python 007_config_baseline_diff.py -d 192.168.1.1 -u admin -p secret --save

    # Check multiple devices listed in a file (one host per line, # = comment)
    python 007_config_baseline_diff.py --hosts-file devices.txt -u admin -p secret

    # Emit a JSON report to a file
    python 007_config_baseline_diff.py -d 192.168.1.1 -u admin -p secret \
        --format json --output report.json

Prerequisites:
    pip install paramiko          (SSH transport)
    Python 3.10+
    Devices must accept SSH password auth.
    Baselines are stored as plain-text files in --baseline-dir (default: ./baselines/).
"""

import argparse
import difflib
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("config-baseline-diff")

SHOW_RUN = "show running-config"
SSH_TIMEOUT = 15
CMD_TIMEOUT = 30


def _fetch_running_config(host: str, username: str, password: str, port: int) -> str:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            port=port,
            username=username,
            password=password,
            timeout=SSH_TIMEOUT,
            look_for_keys=False,
            allow_agent=False,
        )
        _, stdout, stderr = client.exec_command(SHOW_RUN, timeout=CMD_TIMEOUT)
        output = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace").strip()
        if err:
            log.warning("%s stderr: %s", host, err)
        return output
    finally:
        client.close()


def _baseline_path(host: str, baseline_dir: Path) -> Path:
    safe = host.replace(":", "_").replace("/", "_")
    return baseline_dir / f"{safe}.cfg"


def load_baseline(host: str, baseline_dir: Path) -> list[str] | None:
    path = _baseline_path(host, baseline_dir)
    return path.read_text(encoding="utf-8").splitlines(keepends=True) if path.exists() else None


def save_baseline(host: str, config: str, baseline_dir: Path) -> None:
    baseline_dir.mkdir(parents=True, exist_ok=True)
    path = _baseline_path(host, baseline_dir)
    path.write_text(config, encoding="utf-8")
    log.info("%s: baseline saved → %s", host, path)


def audit_device(
    host: str, username: str, password: str, port: int, baseline_dir: Path, save: bool
) -> dict:
    result: dict = {
        "host": host,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": None,
        "diff_lines": 0,
        "diff": [],
        "error": None,
    }

    try:
        log.info("%s: fetching running config", host)
        current = _fetch_running_config(host, username, password, port)
    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        log.error("%s: SSH failed — %s", host, exc)
        return result

    if save:
        save_baseline(host, current, baseline_dir)
        result["status"] = "baseline_saved"
        return result

    baseline = load_baseline(host, baseline_dir)
    if baseline is None:
        log.warning("%s: no baseline on disk; run with --save first", host)
        result["status"] = "no_baseline"
        return result

    diff = list(
        difflib.unified_diff(
            baseline,
            current.splitlines(keepends=True),
            fromfile=f"{host} (baseline)",
            tofile=f"{host} (current)",
            lineterm="",
        )
    )
    result["diff"] = diff
    result["diff_lines"] = len(diff)
    result["status"] = "drift_detected" if diff else "clean"
    if diff:
        log.warning("%s: drift detected — %d diff line(s)", host, len(diff))
    else:
        log.info("%s: no drift", host)
    return result


def format_text(results: list[dict]) -> str:
    sep = "=" * 72
    lines = []
    for r in results:
        lines.append(sep)
        lines.append(f"Host      : {r['host']}")
        lines.append(f"Timestamp : {r['timestamp']}")
        lines.append(f"Status    : {r['status']}")
        if r["error"]:
            lines.append(f"Error     : {r['error']}")
        if r["diff"]:
            lines.append("--- diff ---")
            lines.extend(r["diff"])
    lines.append(sep)
    counts = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    lines.append("Summary: " + "  ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Detect configuration drift by diffing running configs against baselines."
    )
    grp = p.add_mutually_exclusive_group(required=True)
    grp.add_argument("-d", "--device", metavar="HOST", help="Single device hostname or IP")
    grp.add_argument("--hosts-file", metavar="FILE", help="File listing one host per line")
    p.add_argument("-u", "--username", required=True)
    p.add_argument("-p", "--password", required=True)
    p.add_argument("--port", type=int, default=22, metavar="N")
    p.add_argument("--baseline-dir", default="baselines", metavar="DIR")
    p.add_argument("--save", action="store_true", help="Overwrite baseline with current config")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--output", metavar="FILE", help="Write report to FILE (default: stdout)")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main() -> int:
    args = build_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.WARNING)

    if args.hosts_file:
        hosts_path = Path(args.hosts_file)
        if not hosts_path.exists():
            log.error("Hosts file not found: %s", hosts_path)
            return 1
        hosts = [
            ln.strip()
            for ln in hosts_path.read_text().splitlines()
            if ln.strip() and not ln.startswith("#")
        ]
    else:
        hosts = [args.device]

    baseline_dir = Path(args.baseline_dir)
    results = [
        audit_device(h, args.username, args.password, args.port, baseline_dir, args.save)
        for h in hosts
    ]

    report = json.dumps(results, indent=2) if args.format == "json" else format_text(results)

    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        log.info("Report written to %s", args.output)
    else:
        print(report)

    return 1 if any(r["status"] == "drift_detected" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
```
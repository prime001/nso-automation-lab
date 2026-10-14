The user explicitly says "Output ONLY the script content, no markdown fences, no explanation." This direct instruction overrides the brainstorming workflow per skill priority rules.

"""
003_compliance_checker.py — Network Device Configuration Compliance Checker

Purpose:
    SSH into one or more network devices and verify the running configuration
    against a JSON policy file containing regex-based must-match and
    must-not-match rules.  Exits non-zero when violations are found, making it
    suitable as a CI/CD gate or scheduled audit job.

Usage:
    python 003_compliance_checker.py --host 10.0.0.1 --username admin \
        --password secret --policy policies/ios_baseline.json

    python 003_compliance_checker.py --hosts hosts.txt --username admin \
        --key-file ~/.ssh/id_rsa --policy policies/ios_baseline.json \
        --output report.json --fail-on-violation

Prerequisites:
    pip install paramiko
    Python 3.9+

Policy file format (JSON):
    {
      "name": "IOS Baseline v1",
      "must_match": [
        {"id": "NTP-01", "pattern": "ntp server 10\\.0\\.0\\.1", "desc": "Primary NTP configured"},
        {"id": "LOG-01", "pattern": "logging host",              "desc": "Syslog server present"}
      ],
      "must_not_match": [
        {"id": "SEC-01", "pattern": "enable password ",          "desc": "Cleartext enable password prohibited"},
        {"id": "SEC-02", "pattern": "no service password-encryption", "desc": "Password encryption required"}
      ]
    }
"""

import argparse
import json
import logging
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

try:
    import paramiko
except ImportError:
    print("ERROR: paramiko is required.  Run: pip install paramiko", file=sys.stderr)
    sys.exit(1)

logger = logging.getLogger(__name__)


@dataclass
class CheckResult:
    check_id: str
    description: str
    kind: str          # "must_match" | "must_not_match"
    passed: bool
    evidence: Optional[str] = None


@dataclass
class DeviceReport:
    host: str
    connected: bool
    error: Optional[str] = None
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.connected and all(c.passed for c in self.checks)

    @property
    def violations(self) -> list[CheckResult]:
        return [c for c in self.checks if not c.passed]


def _connect(host: str, port: int, username: str,
             password: Optional[str], key_file: Optional[str],
             timeout: int) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs: dict = dict(hostname=host, port=port, username=username,
                        timeout=timeout, look_for_keys=False, allow_agent=False)
    if key_file:
        kwargs["key_filename"] = key_file
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def _fetch_config(client: paramiko.SSHClient, show_cmd: str) -> str:
    _, stdout, stderr = client.exec_command(show_cmd, timeout=30)
    exit_code = stdout.channel.recv_exit_status()
    output = stdout.read().decode(errors="replace")
    if exit_code != 0:
        err = stderr.read().decode(errors="replace").strip()
        raise RuntimeError(f"Command exited {exit_code}: {err}")
    return output


def evaluate_policy(config: str, policy: dict) -> list[CheckResult]:
    results: list[CheckResult] = []
    for rule in policy.get("must_match", []):
        m = re.search(rule["pattern"], config, re.MULTILINE)
        results.append(CheckResult(rule["id"], rule["desc"], "must_match",
                                   bool(m), m.group(0) if m else None))
    for rule in policy.get("must_not_match", []):
        m = re.search(rule["pattern"], config, re.MULTILINE)
        results.append(CheckResult(rule["id"], rule["desc"], "must_not_match",
                                   not bool(m), m.group(0) if m else None))
    return results


def check_device(host: str, port: int, username: str, password: Optional[str],
                 key_file: Optional[str], policy: dict,
                 timeout: int, show_cmd: str) -> DeviceReport:
    report = DeviceReport(host=host, connected=False)
    client: Optional[paramiko.SSHClient] = None
    try:
        logger.info("Connecting to %s:%d", host, port)
        client = _connect(host, port, username, password, key_file, timeout)
        report.connected = True
        config = _fetch_config(client, show_cmd)
        report.checks = evaluate_policy(config, policy)
        logger.info("%s — %d checks, %d violation(s)",
                    host, len(report.checks), len(report.violations))
    except paramiko.AuthenticationException:
        report.error = "Authentication failed"
        logger.error("%s: %s", host, report.error)
    except (paramiko.SSHException, OSError) as exc:
        report.error = f"Connection error: {exc}"
        logger.error("%s: %s", host, report.error)
    except Exception as exc:
        report.error = f"Unexpected error: {exc}"
        logger.exception("%s: unexpected", host)
    finally:
        if client:
            client.close()
    return report


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Verify network device running-config against a compliance policy.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    tgt = p.add_mutually_exclusive_group(required=True)
    tgt.add_argument("--host", metavar="IP", help="Single target device")
    tgt.add_argument("--hosts", metavar="FILE", help="Newline-delimited host list")

    cred = p.add_argument_group("credentials")
    cred.add_argument("--username", required=True)
    pw = cred.add_mutually_exclusive_group(required=True)
    pw.add_argument("--password", help="SSH password")
    pw.add_argument("--key-file", metavar="PATH", help="SSH private key path")

    p.add_argument("--policy", required=True, metavar="JSON",
                   help="Path to compliance policy JSON file")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--timeout", type=int, default=15, help="SSH connect timeout (s)")
    p.add_argument("--show-cmd", default="show running-config",
                   help="Command to retrieve device configuration")
    p.add_argument("--output", metavar="FILE",
                   help="Write JSON report to FILE instead of stdout")
    p.add_argument("--fail-on-violation", action="store_true",
                   help="Exit 1 if any device has violations (CI gate mode)")
    p.add_argument("--verbose", "-v", action="store_true")
    return p


def main() -> int:
    args = build_parser().parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    try:
        policy_path = Path(args.policy)
        policy: dict = json.loads(policy_path.read_text())
        policy.setdefault("must_match", [])
        policy.setdefault("must_not_match", [])
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("Failed to load policy: %s", exc)
        return 2

    if args.host:
        hosts = [args.host.strip()]
    else:
        try:
            hosts = [h.strip() for h in Path(args.hosts).read_text().splitlines() if h.strip()]
        except OSError as exc:
            logger.error("Cannot read hosts file: %s", exc)
            return 2

    reports = [
        check_device(h, args.port, args.username, args.password,
                     args.key_file, policy, args.timeout, args.show_cmd)
        for h in hosts
    ]

    summary = {
        "policy": policy.get("name", args.policy),
        "total": len(reports),
        "compliant": sum(1 for r in reports if r.passed),
        "non_compliant": sum(1 for r in reports if not r.passed),
        "devices": [
            {**asdict(r), "passed": r.passed, "violation_count": len(r.violations)}
            for r in reports
        ],
    }

    payload = json.dumps(summary, indent=2)
    if args.output:
        Path(args.output).write_text(payload)
        logger.info("Report written to %s", args.output)
    else:
        print(payload)

    return 1 if args.fail_on_violation and summary["non_compliant"] > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
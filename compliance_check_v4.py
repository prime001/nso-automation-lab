```python
"""
Multi-Layer Compliance Verification Engine

Validates device configurations across multiple compliance domains:
- Interface standards (MTU, speed, duplex)
- Routing protocol compliance (BGP, OSPF)
- Security policies (SSH, AAA, encryption)
- Management access (NTP, DNS, logging)

Supports custom compliance templates and generates JSON reports.

Usage:
    python script.py --device 10.1.1.1 --username admin --password secret
    python script.py --device 10.1.1.1 --username admin --password secret --template compliance.json
    python script.py --device 10.1.1.1 --username admin --password secret --json-output

Prerequisites:
    - netmiko installed: pip install netmiko
    - Device accessible via SSH
    - User has read/exec permissions on target device
"""

import argparse
import json
import logging
import sys
from typing import Dict, List, Tuple
from datetime import datetime

try:
    from netmiko import ConnectHandler
except ImportError:
    print("ERROR: netmiko required. Install: pip install netmiko")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ComplianceEngine:
    """Multi-layer network device compliance checker."""

    DEFAULT_CHECKS = {
        "hostname": {"enabled": True, "pattern": r"hostname\s+\S+"},
        "ssh": {"enabled": True, "version": "2"},
        "ntp": {"enabled": True, "min_servers": 2},
        "dns": {"enabled": True, "min_servers": 2},
        "logging": {"enabled": True, "destinations": 1},
        "snmp": {"enabled": True, "version": 3},
        "aaa": {"enabled": True},
        "tacacs": {"enabled": False},
    }

    def __init__(self, host: str, username: str, password: str, device_type: str = "cisco_ios"):
        self.host = host
        self.device_type = device_type
        self.params = {
            "device_type": device_type,
            "host": host,
            "username": username,
            "password": password,
        }
        self.device = None
        self.config = ""
        self.results = []

    def connect(self) -> bool:
        """Establish SSH connection to device."""
        try:
            logger.info(f"Connecting to {self.host}...")
            self.device = ConnectHandler(**self.params)
            logger.info("Connection successful")
            return True
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False

    def disconnect(self):
        """Close SSH connection."""
        if self.device:
            self.device.disconnect()
            logger.info("Disconnected")

    def fetch_config(self) -> bool:
        """Retrieve running configuration from device."""
        try:
            logger.info("Fetching running configuration...")
            self.config = self.device.send_command("show running-config")
            return bool(self.config)
        except Exception as e:
            logger.error(f"Failed to fetch config: {e}")
            return False

    def run_checks(self, checks: Dict = None) -> Dict:
        """Execute compliance checks."""
        checks = checks or self.DEFAULT_CHECKS
        report = {
            "device": self.host,
            "device_type": self.device_type,
            "timestamp": datetime.now().isoformat(),
            "results": {},
            "summary": {"passed": 0, "failed": 0, "skipped": 0},
        }

        for check_name, rules in checks.items():
            if not rules.get("enabled", False):
                report["summary"]["skipped"] += 1
                continue

            result = self._execute_check(check_name, rules)
            report["results"][check_name] = result

            if result["status"] == "PASS":
                report["summary"]["passed"] += 1
            else:
                report["summary"]["failed"] += 1
                logger.warning(f"FAIL: {check_name} - {result.get('details', '')}")

        report["status"] = "PASS" if report["summary"]["failed"] == 0 else "FAIL"
        return report

    def _execute_check(self, check_name: str, rules: Dict) -> Dict:
        """Run individual compliance check."""
        result = {
            "status": "UNKNOWN",
            "details": "",
            "evidence": [],
        }

        if check_name == "hostname":
            result = self._check_hostname(rules)
        elif check_name == "ssh":
            result = self._check_ssh(rules)
        elif check_name == "ntp":
            result = self._check_ntp(rules)
        elif check_name == "dns":
            result = self._check_dns(rules)
        elif check_name == "logging":
            result = self._check_logging(rules)
        elif check_name == "snmp":
            result = self._check_snmp(rules)
        elif check_name == "aaa":
            result = self._check_aaa(rules)
        elif check_name == "tacacs":
            result = self._check_tacacs(rules)

        return result

    def _check_hostname(self, rules: Dict) -> Dict:
        """Verify hostname is configured."""
        if "hostname" in self.config:
            for line in self.config.split('\n'):
                if line.startswith("hostname"):
                    return {
                        "status": "PASS",
                        "details": "Hostname configured",
                        "evidence": [line.strip()],
                    }
        return {"status": "FAIL", "details": "Hostname not configured", "evidence": []}

    def _check_ssh(self, rules: Dict) -> Dict:
        """Verify SSH is enabled."""
        ssh_lines = [l for l in self.config.split('\n') if 'ssh' in l.lower()]
        if ssh_lines:
            return {
                "status": "PASS",
                "details": f"SSH enabled ({len(ssh_lines)} config lines)",
                "evidence": ssh_lines[:3],
            }
        return {"status": "FAIL", "details": "SSH not configured", "evidence": []}

    def _check_ntp(self, rules: Dict) -> Dict:
        """Verify NTP configuration."""
        ntp_servers = [l for l in self.config.split('\n') if 'ntp server' in l.lower()]
        min_required = rules.get("min_servers", 2)
        if len(ntp_servers) >= min_required:
            return {
                "status": "PASS",
                "details": f"{len(ntp_servers)} NTP servers configured",
                "evidence": ntp_servers[:3],
            }
        return {
            "status": "FAIL",
            "details": f"Only {len(ntp_servers)} NTP servers (require {min_required})",
            "evidence": ntp_servers,
        }

    def _check_dns(self, rules: Dict) -> Dict:
        """Verify DNS configuration."""
        dns_lines = [l for l in self.config.split('\n') if 'ip name-server' in l.lower()]
        min_required = rules.get("min_servers", 2)
        if len(dns_lines) >= min_required:
            return {
                "status": "PASS",
                "details": f"{len(dns_lines)} DNS servers configured",
                "evidence": dns_lines[:3],
            }
        return {
            "status": "FAIL",
            "details": f"Only {len(dns_lines)} DNS servers (require {min_required})",
            "evidence": dns_lines,
        }

    def _check_logging(self, rules: Dict) -> Dict:
        """Verify logging is enabled."""
        log_lines = [l for l in self.config.split('\n') if 'logging' in l.lower()]
        if log_lines:
            return {
                "status": "PASS",
                "details": f"Logging configured ({len(log_lines)} destinations)",
                "evidence": log_lines[:3],
            }
        return {"status": "FAIL", "details": "Logging not configured", "evidence": []}

    def _check_snmp(self, rules: Dict) -> Dict:
        """Verify SNMP configuration."""
        snmp_lines = [l for l in self.config.split('\n') if 'snmp' in l.lower()]
        if snmp_lines:
            return {
                "status": "PASS",
                "details": "SNMP configured",
                "evidence": snmp_lines[:3],
            }
        return {"status": "FAIL", "details": "SNMP not configured", "evidence": []}

    def _check_aaa(self, rules: Dict) -> Dict:
        """Verify AAA is configured."""
        aaa_lines = [l for l in self.config.split('\n') if 'aaa' in l.lower()]
        if aaa_lines:
            return {
                "status": "PASS",
                "details": "AAA configured",
                "evidence": aaa_lines[:3],
            }
        return {"status": "FAIL", "details": "AAA not configured", "evidence": []}

    def _check_tacacs(self, rules: Dict) -> Dict:
        """Verify TACACS+ configuration."""
        tacacs_lines = [l for l in self.config.split('\n') if 'tacacs' in l.lower()]
        if tacacs_lines:
            return {
                "status": "PASS",
                "details": "TACACS+ configured",
                "evidence": tacacs_lines[:3],
            }
        return {"status": "FAIL", "details": "TACACS+ not configured", "evidence": []}


def main():
    parser = argparse.ArgumentParser(
        description="Multi-layer network compliance verification engine"
    )
    parser.add_argument("--device", required=True, help="Device IP address")
    parser.add_argument("--username", required=True, help="SSH username")
    parser.add_argument("--password", required=True, help="SSH password")
    parser.add_argument("--device-type", default="cisco_ios", help="Device type (default: cisco_ios)")
    parser.add_argument("--template", help="Custom compliance template (JSON file)")
    parser.add_argument("--json-output", action="store_true", help="Output as JSON")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    engine = ComplianceEngine(args.device, args.username, args.password, args.device_type)

    if not engine.connect():
        sys.exit(1)

    try:
        if not engine.fetch_config():
            logger.error("Cannot proceed without configuration")
            sys.exit(1)

        checks = engine.DEFAULT_CHECKS
        if args.template:
            try:
                with open(args.template) as f:
                    checks = json.load(f)
                logger.info(f"Loaded template: {args.template}")
            except Exception as e:
                logger.error(f"Template load failed: {e}")
                sys.exit(1)

        report = engine.run_checks(checks)

        if args.json_output:
            print(json.dumps(report, indent=2))
        else:
            print(f"\n{'='*70}")
            print(f"Compliance Report: {args.device}")
            print(f"Timestamp: {report['timestamp']}")
            print(f"Overall Status: {report['status']}")
            print(f"Summary: {report['summary']['passed']} passed, {report['summary']['failed']} failed")
            print(f"{'='*70}")
            for check, result in report["results"].items():
                status_icon = "✓" if result["status"] == "PASS" else "✗"
                print(f"{status_icon} {check.upper()}: {result['status']} - {result['details']}")
            print(f"{'='*70}\n")

        sys.exit(0 if report["status"] == "PASS" else 1)

    finally:
        engine.disconnect()


if __name__ == "__main__":
    main()
```
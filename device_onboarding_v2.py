```python
"""
Bulk Device Onboarding from Inventory

Purpose:
    Import and onboard multiple network devices to NSO from a CSV or JSON inventory file.
    Validates device connectivity, authenticates to NSO API, and performs initial sync.

Usage:
    python bulk_device_onboarding.py \
        --inventory devices.csv \
        --nso-host 192.168.1.100 \
        --nso-user admin \
        --nso-password admin

Inventory Format (CSV):
    name,ip,username,password,device_type
    device1,192.168.1.10,netadmin,password123,cisco-ios

Prerequisites:
    - NSO controller accessible and running (HTTPS API)
    - Device SSH credentials valid
    - Paramiko for SSH connectivity checks
    - Requests library for NSO REST API
"""

import argparse
import csv
import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import paramiko
import requests
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)


class NSODeviceOnboarder:
    """Bulk device onboarding orchestrator for NSO."""

    def __init__(self, nso_host: str, nso_user: str, nso_pass: str, nso_port: int = 8080):
        """Initialize NSO API connection."""
        self.nso_host = nso_host
        self.nso_port = nso_port
        self.base_url = f"https://{nso_host}:{nso_port}/api"
        self.session = requests.Session()
        self.session.auth = HTTPBasicAuth(nso_user, nso_pass)
        self.session.verify = False
        self.session.headers.update({"Content-Type": "application/yang-data+json"})
        
        self.stats = {"attempted": 0, "success": 0, "failed": 0, "failures": []}

    def test_ssh_connectivity(self, device: Dict) -> bool:
        """Verify SSH access to device."""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            ssh.connect(
                hostname=device["ip"],
                username=device.get("username"),
                password=device.get("password"),
                timeout=10,
                allow_agent=False,
                look_for_keys=False
            )
            ssh.close()
            logger.debug(f"SSH connectivity verified for {device['name']}")
            return True
        except (paramiko.AuthenticationException, paramiko.SSHException, Exception) as e:
            logger.warning(f"SSH test failed for {device['name']}: {str(e)}")
            return False

    def add_device_to_nso(self, device: Dict) -> Tuple[bool, str]:
        """Add device to NSO configuration database."""
        payload = {
            "devices:device": [
                {
                    "name": device["name"],
                    "address": device["ip"],
                    "authgroup": device.get("authgroup", "default"),
                    "device-type": device.get("device_type", "cli"),
                    "protocol": device.get("protocol", "ssh")
                }
            ]
        }
        
        try:
            resp = self.session.post(
                f"{self.base_url}/config/devices/device",
                json=payload,
                timeout=30
            )
            
            if resp.status_code in (200, 201, 204):
                logger.info(f"Device {device['name']} added to NSO")
                return True, "Added to NSO"
            else:
                error = f"HTTP {resp.status_code}: {resp.text[:100]}"
                logger.error(f"Failed to add {device['name']}: {error}")
                return False, error
        except requests.exceptions.RequestException as e:
            logger.error(f"API error for {device['name']}: {str(e)}")
            return False, str(e)

    def sync_from_device(self, device_name: str) -> Tuple[bool, str]:
        """Trigger sync-from to pull device state into NSO."""
        try:
            resp = self.session.post(
                f"{self.base_url}/config/devices/device/{device_name}/sync-from",
                timeout=30
            )
            
            if resp.status_code in (200, 201, 204):
                logger.info(f"Device {device_name} synced successfully")
                return True, "Sync successful"
            else:
                error = f"HTTP {resp.status_code}"
                logger.warning(f"Sync failed for {device_name}: {error}")
                return False, error
        except requests.exceptions.RequestException as e:
            return False, str(e)

    def onboard_device(self, device: Dict) -> bool:
        """Complete onboarding workflow for a single device."""
        self.stats["attempted"] += 1
        
        # Test SSH connectivity
        if not self.test_ssh_connectivity(device):
            self.stats["failed"] += 1
            self.stats["failures"].append((device["name"], "SSH connectivity failed"))
            return False
        
        # Add to NSO
        added, msg = self.add_device_to_nso(device)
        if not added:
            self.stats["failed"] += 1
            self.stats["failures"].append((device["name"], f"NSO add failed: {msg}"))
            return False
        
        # Perform initial sync
        synced, msg = self.sync_from_device(device["name"])
        if not synced:
            self.stats["failed"] += 1
            self.stats["failures"].append((device["name"], f"Sync failed: {msg}"))
            return False
        
        self.stats["success"] += 1
        return True

    def process_inventory(self, devices: List[Dict]) -> Dict:
        """Onboard all devices from inventory."""
        logger.info(f"Starting onboarding of {len(devices)} device(s)")
        
        for device in devices:
            try:
                self.onboard_device(device)
            except Exception as e:
                logger.error(f"Unexpected error for {device['name']}: {str(e)}")
                self.stats["failed"] += 1
                self.stats["failures"].append((device["name"], str(e)))
        
        return self.stats


def load_inventory(filepath: str) -> List[Dict]:
    """Load device inventory from CSV or JSON file."""
    path = Path(filepath)
    
    if not path.exists():
        raise FileNotFoundError(f"Inventory file not found: {filepath}")
    
    devices = []
    
    try:
        if path.suffix == ".json":
            with open(path) as f:
                devices = json.load(f)
        elif path.suffix == ".csv":
            with open(path) as f:
                reader = csv.DictReader(f)
                devices = list(reader)
        else:
            raise ValueError("File must be .csv or .json")
        
        if not devices:
            raise ValueError("Inventory file is empty")
        
        logger.info(f"Loaded {len(devices)} device(s) from {filepath}")
        return devices
    
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in inventory: {e}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Bulk onboard devices to NSO")
    parser.add_argument("--inventory", required=True, help="Inventory file (CSV or JSON)")
    parser.add_argument("--nso-host", required=True, help="NSO hostname/IP")
    parser.add_argument("--nso-user", required=True, help="NSO username")
    parser.add_argument("--nso-password", required=True, help="NSO password")
    parser.add_argument("--nso-port", type=int, default=8080, help="NSO port")
    parser.add_argument("--log-level", default="INFO", help="Logging level")
    
    args = parser.parse_args()
    
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    try:
        devices = load_inventory(args.inventory)
        onboarder = NSODeviceOnboarder(
            args.nso_host, args.nso_user, args.nso_password, args.nso_port
        )
        stats = onboarder.process_inventory(devices)
        
        logger.info("=" * 60)
        logger.info(f"Onboarding complete: {stats['success']}/{stats['attempted']} successful")
        
        if stats["failures"]:
            logger.warning("Failed devices:")
            for name, reason in stats["failures"]:
                logger.warning(f"  - {name}: {reason}")
        
        return 0 if stats["failed"] == 0 else 1
    
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
```
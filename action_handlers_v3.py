```python
#!/usr/bin/env python3
"""
Device State Synchronizer - Discover, compare, and sync device state.

Purpose:
    Compare actual device state against desired configuration and report/fix discrepancies.
    Uses NAPALM for cross-platform state gathering and Netmiko for remediation.

Usage:
    python 021_device_state_sync.py --device 10.0.0.1 --device-type cisco_ios \
        --username admin --password secret --desired-state state.json

Prerequisites:
    - Device must be reachable and credentials valid
    - NAPALM supported device type
    - Desired state JSON file with target interface/routing config
    - netmiko and napalm libraries installed

Author: Network Automation Lab
"""

import argparse
import json
import logging
import sys
from typing import Any, Dict, List

try:
    from napalm import get_network_driver
    from netmiko import ConnectHandler
except ImportError as e:
    print(f"Error: Required library not found: {e}")
    sys.exit(1)


def setup_logging(debug: bool = False) -> logging.Logger:
    """Configure logging with appropriate verbosity."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    return logging.getLogger(__name__)


def load_desired_state(filepath: str) -> Dict[str, Any]:
    """Load desired state from JSON file."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        raise ValueError(f"Desired state file not found: {filepath}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in desired state file: {e}")


def get_device_facts(device_params: Dict[str, str]) -> Dict[str, Any]:
    """Retrieve device facts and interface status using NAPALM."""
    driver = get_network_driver(device_params['device_type'])
    with driver(**device_params) as device:
        facts = device.get_facts()
        interfaces = device.get_interfaces()
        return {
            'facts': facts,
            'interfaces': interfaces
        }


def compare_state(current: Dict[str, Any],
                  desired: Dict[str, Any]) -> Dict[str, List[str]]:
    """Compare current vs desired state and identify discrepancies."""
    discrepancies = {
        'missing_interfaces': [],
        'interface_mismatch': [],
        'other': []
    }

    desired_interfaces = desired.get('interfaces', {})
    current_interfaces = current.get('interfaces', {})

    for iface in desired_interfaces:
        if iface not in current_interfaces:
            discrepancies['missing_interfaces'].append(iface)

    for iface, desired_props in desired_interfaces.items():
        if iface in current_interfaces:
            current_props = current_interfaces[iface]
            for prop, desired_val in desired_props.items():
                current_val = current_props.get(prop)
                if current_val != desired_val:
                    discrepancies['interface_mismatch'].append(
                        f"{iface}.{prop}: {current_val} != {desired_val}"
                    )

    return discrepancies


def apply_remediation(device_params: Dict[str, str],
                      discrepancies: Dict[str, List[str]],
                      logger: logging.Logger) -> bool:
    """Apply remediation commands to address discovered discrepancies."""
    if not any(discrepancies.values()):
        logger.info("No discrepancies found. Device is in desired state.")
        return True

    try:
        conn = ConnectHandler(**device_params)
        commands = []

        for iface in discrepancies.get('missing_interfaces', []):
            commands.append(f"interface {iface}")
            commands.append("no shutdown")

        if commands:
            logger.info(f"Sending {len(commands)} remediation commands...")
            output = conn.send_config_set(commands)
            logger.debug(f"Remediation output: {output}")
            conn.disconnect()
            return True
    except Exception as e:
        logger.error(f"Failed to apply remediation: {e}")
        return False

    return True


def main() -> int:
    """Main execution logic."""
    parser = argparse.ArgumentParser(
        description="Synchronize device state against desired configuration",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--device', required=True,
                        help='Device IP or hostname')
    parser.add_argument('--device-type', required=True,
                        help='NAPALM device type (e.g., cisco_ios)')
    parser.add_argument('--username', required=True,
                        help='Device username')
    parser.add_argument('--password', required=True,
                        help='Device password')
    parser.add_argument('--desired-state', required=True,
                        help='Path to desired state JSON file')
    parser.add_argument('--port', type=int, default=22,
                        help='SSH port (default: 22)')
    parser.add_argument('--remediate', action='store_true',
                        help='Apply remediation commands')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug logging')

    args = parser.parse_args()
    logger = setup_logging(args.debug)

    device_params = {
        'device_type': args.device_type,
        'host': args.device,
        'username': args.username,
        'password': args.password,
        'port': args.port,
    }

    try:
        logger.info(f"Connecting to {args.device}...")
        current_state = get_device_facts(device_params)
        logger.info("Successfully retrieved device facts")

        logger.info(f"Loading desired state from {args.desired_state}...")
        desired_state = load_desired_state(args.desired_state)

        logger.info("Comparing state...")
        discrepancies = compare_state(current_state, desired_state)

        if any(discrepancies.values()):
            logger.warning("Discrepancies found:")
            for category, items in discrepancies.items():
                if items:
                    logger.warning(f"  {category}: {items}")

            if args.remediate:
                logger.info("Applying remediation...")
                apply_remediation(device_params, discrepancies, logger)
            else:
                logger.info("Use --remediate flag to apply fixes")
        else:
            logger.info("Device state matches desired configuration")

        return 0

    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=args.debug)
        return 1


if __name__ == "__main__":
    sys.exit(main())
```
#!/usr/bin/env python3
"""
BGP Neighbor Validation and Health Metrics Collection.

Purpose:
    Validates BGP neighbor status and collects health metrics from network
    devices using SSH and CLI parsing. Reports neighbor state, message counts,
    and alerts on unhealthy sessions.

Prerequisites:
    - Device with BGP configured
    - netmiko library installed (pip install netmiko)
    - SSH/telnet access with valid credentials

Usage:
    python3 bgp_health_monitor.py --device 192.168.1.1 --username admin --password secret
    python3 bgp_health_monitor.py --device 192.168.1.1 --device-type cisco_ios --format json
    python3 bgp_health_monitor.py --device 10.0.0.5 --threshold 500 --verbose
"""

import argparse
import json
import logging
import sys
from datetime import datetime

try:
    from netmiko import ConnectHandler
except ImportError:
    print("Error: netmiko not installed. Run: pip install netmiko")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class BGPHealthMonitor:
    """Monitor BGP neighbor status and health metrics."""

    def __init__(self, device_ip, username, password, device_type='cisco_ios',
                 port=22, timeout=30):
        """Initialize monitor with device connection parameters."""
        self.device_ip = device_ip
        self.username = username
        self.password = password
        self.device_type = device_type
        self.port = port
        self.timeout = timeout
        self.connection = None

    def connect(self):
        """Establish SSH connection to device."""
        try:
            device_params = {
                'device_type': self.device_type,
                'ip': self.device_ip,
                'username': self.username,
                'password': self.password,
                'port': self.port,
                'timeout': self.timeout,
                'auth_timeout': self.timeout,
            }
            self.connection = ConnectHandler(**device_params)
            logger.info(f"Connected to {self.device_ip}")
            return True
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False

    def get_bgp_neighbors(self):
        """Retrieve and parse BGP neighbor summary."""
        if not self.connection:
            logger.error("Not connected to device")
            return []

        try:
            if 'juniper' in self.device_type:
                cmd = 'show bgp summary'
            elif 'arista' in self.device_type:
                cmd = 'show bgp summary'
            else:
                cmd = 'show bgp all summary'

            output = self.connection.send_command(cmd)
            neighbors = self._parse_neighbors(output)
            logger.info(f"Parsed {len(neighbors)} BGP neighbors")
            return neighbors
        except Exception as e:
            logger.error(f"Failed to retrieve BGP data: {e}")
            return []

    def _parse_neighbors(self, output):
        """Parse BGP summary output into structured data."""
        neighbors = []
        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith(' ') or 'Neighbor' in line:
                continue
            
            parts = line.split()
            if len(parts) < 6:
                continue

            try:
                neighbor = {
                    'ip': parts[0],
                    'asn': parts[2],
                    'msgs_rcvd': int(parts[3]) if parts[3].isdigit() else 0,
                    'msgs_sent': int(parts[4]) if parts[4].isdigit() else 0,
                    'uptime': parts[5],
                    'state': ' '.join(parts[6:]) if len(parts) > 6 else 'unknown',
                }
                neighbors.append(neighbor)
            except (ValueError, IndexError):
                logger.debug(f"Failed to parse line: {line}")
                continue

        return neighbors

    def validate(self, neighbors, msg_threshold=100):
        """Validate neighbor health against thresholds."""
        healthy_count = sum(
            1 for n in neighbors if 'up' in n['state'].lower()
        )
        unhealthy = [
            n for n in neighbors if 'up' not in n['state'].lower()
        ]
        low_messages = [
            n for n in neighbors
            if n['msgs_rcvd'] < msg_threshold and 'up' in n['state'].lower()
        ]

        return {
            'timestamp': datetime.now().isoformat(),
            'device': self.device_ip,
            'total': len(neighbors),
            'healthy': healthy_count,
            'unhealthy': len(unhealthy),
            'low_message_count': len(low_messages),
            'neighbors': neighbors,
            'alerts': unhealthy + low_messages,
        }

    def disconnect(self):
        """Close SSH connection."""
        if self.connection:
            try:
                self.connection.disconnect()
                logger.info(f"Disconnected from {self.device_ip}")
            except Exception as e:
                logger.warning(f"Disconnect error: {e}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor BGP neighbor health and metrics on network devices'
    )
    parser.add_argument('--device', required=True, help='Target device IP address')
    parser.add_argument('--username', default='admin', help='SSH username')
    parser.add_argument('--password', required=True, help='SSH password')
    parser.add_argument('--device-type', default='cisco_ios',
                       help='Device type for netmiko (cisco_ios, juniper_junos, arista_eos)')
    parser.add_argument('--port', type=int, default=22, help='SSH port')
    parser.add_argument('--timeout', type=int, default=30, help='Connection timeout (seconds)')
    parser.add_argument('--threshold', type=int, default=100,
                       help='Message count threshold for warnings')
    parser.add_argument('--format', choices=['text', 'json'], default='text',
                       help='Output format')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    monitor = BGPHealthMonitor(
        device_ip=args.device,
        username=args.username,
        password=args.password,
        device_type=args.device_type,
        port=args.port,
        timeout=args.timeout
    )

    if not monitor.connect():
        sys.exit(1)

    try:
        neighbors = monitor.get_bgp_neighbors()
        if not neighbors:
            logger.error("No BGP neighbors found or unable to parse output")
            sys.exit(1)

        results = monitor.validate(neighbors, args.threshold)

        if args.format == 'json':
            print(json.dumps(results, indent=2))
        else:
            print(f"\n{'='*60}")
            print(f"BGP Health Report - {results['device']}")
            print(f"Timestamp: {results['timestamp']}")
            print(f"{'='*60}")
            print(f"Total Neighbors:      {results['total']}")
            print(f"Healthy:              {results['healthy']}")
            print(f"Unhealthy:            {results['unhealthy']}")
            print(f"Low Message Count:    {results['low_message_count']}")

            if results['alerts']:
                print(f"\nAlerts ({len(results['alerts'])} neighbors):")
                for neighbor in results['alerts']:
                    state_str = neighbor['state']
                    msg_str = f"{neighbor['msgs_rcvd']}/{neighbor['msgs_sent']}"
                    print(f"  {neighbor['ip']:20} State: {state_str:15} "
                         f"Messages: {msg_str}")
            else:
                print("\nNo alerts - all neighbors healthy!")

    finally:
        monitor.disconnect()


if __name__ == '__main__':
    main()
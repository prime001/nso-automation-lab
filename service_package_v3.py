```python
#!/usr/bin/env python3
"""
Interface Health Monitor - NSO Device Interface Status Monitoring

Purpose:
    Monitor interface health metrics on network devices via SSH.
    Detect issues like high error rates, state changes, and flapping interfaces.
    Generate alerts and generate reports for troubleshooting.

Usage:
    python3 026_interface_health_monitor.py --device 192.168.1.1 \
        --username admin --password secret \
        [--error-threshold 100] [--output report.json]

Prerequisites:
    - Network device reachable via SSH
    - Valid credentials with show command permissions
    - netmiko library installed (pip install netmiko)
    - Python 3.7+

Example:
    Monitor device with high error threshold:
    python3 026_interface_health_monitor.py \
        --device 192.168.1.1 \
        --username netadmin \
        --password P@ssw0rd \
        --device-type cisco_ios \
        --error-threshold 500 \
        --output health_report.json
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from netmiko import ConnectHandler
from netmiko.ssh_exception import SSHException, NetmikoTimeoutException


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class InterfaceHealthMonitor:
    """Monitor interface health metrics and generate alerts."""
    
    def __init__(self, device_ip, username, password, device_type='cisco_ios', error_threshold=100):
        """Initialize monitor with device connection parameters."""
        self.device_ip = device_ip
        self.username = username
        self.password = password
        self.device_type = device_type
        self.error_threshold = error_threshold
        self.connection = None
        self.interface_history = {}
    
    def connect(self):
        """Establish SSH connection to device."""
        try:
            self.connection = ConnectHandler(
                device_type=self.device_type,
                host=self.device_ip,
                username=self.username,
                password=self.password,
                timeout=30
            )
            logger.info(f"Connected to {self.device_ip}")
            return True
        except (SSHException, NetmikoTimeoutException) as e:
            logger.error(f"Connection failed: {e}")
            return False
    
    def get_interface_status(self):
        """Retrieve interface status from device."""
        try:
            output = self.connection.send_command('show interfaces')
            return self._parse_interfaces(output)
        except Exception as e:
            logger.error(f"Failed to retrieve interface status: {e}")
            return {}
    
    def _parse_interfaces(self, output):
        """Parse interface output into structured data."""
        interfaces = {}
        current_iface = None
        
        for line in output.split('\n'):
            if line and not line[0].isspace():
                current_iface = line.split()[0]
                interfaces[current_iface] = {'status': 'unknown', 'errors': 0}
            elif current_iface and 'up' in line.lower():
                status = 'up' if line.split()[0].lower().startswith('up') else 'down'
                interfaces[current_iface]['status'] = status
            elif current_iface and 'errors' in line.lower():
                try:
                    error_count = int(line.split(',')[0].split()[-1])
                    interfaces[current_iface]['errors'] = error_count
                except (ValueError, IndexError):
                    pass
        
        return interfaces
    
    def analyze_interfaces(self, current):
        """Analyze interfaces for health issues."""
        alerts = []
        
        for iface, data in current.items():
            alert = {
                'interface': iface,
                'timestamp': datetime.now().isoformat(),
                'severity': 'INFO',
                'issues': []
            }
            
            if data['status'] == 'down':
                alert['severity'] = 'CRITICAL'
                alert['issues'].append('Interface is DOWN')
            
            if data['errors'] > self.error_threshold:
                alert['severity'] = 'WARNING'
                alert['issues'].append(f"High error rate: {data['errors']}")
            
            if iface in self.interface_history:
                prev_status = self.interface_history[iface].get('status')
                if prev_status and prev_status != data['status']:
                    alert['severity'] = 'WARNING'
                    alert['issues'].append(f"State change detected: {prev_status} -> {data['status']}")
            
            if alert['issues']:
                alerts.append(alert)
            
            self.interface_history[iface] = data
        
        return alerts
    
    def disconnect(self):
        """Close SSH connection."""
        if self.connection:
            self.connection.disconnect()
            logger.info("Disconnected from device")
    
    def generate_report(self, alerts, output_file=None):
        """Generate health report from alerts."""
        report = {
            'device': self.device_ip,
            'timestamp': datetime.now().isoformat(),
            'alert_count': len(alerts),
            'critical_count': sum(1 for a in alerts if a['severity'] == 'CRITICAL'),
            'warning_count': sum(1 for a in alerts if a['severity'] == 'WARNING'),
            'alerts': alerts
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"Report saved to {output_file}")
        
        return json.dumps(report, indent=2)


def main():
    """CLI entry point for interface health monitoring."""
    parser = argparse.ArgumentParser(
        description='Monitor network device interface health metrics'
    )
    parser.add_argument('--device', required=True, help='Device IP address')
    parser.add_argument('--username', required=True, help='SSH username')
    parser.add_argument('--password', required=True, help='SSH password')
    parser.add_argument(
        '--device-type',
        default='cisco_ios',
        help='Netmiko device type (default: cisco_ios)'
    )
    parser.add_argument(
        '--error-threshold',
        type=int,
        default=100,
        help='Error count threshold for alerts (default: 100)'
    )
    parser.add_argument('--output', help='Save report to JSON file')
    
    args = parser.parse_args()
    
    monitor = InterfaceHealthMonitor(
        device_ip=args.device,
        username=args.username,
        password=args.password,
        device_type=args.device_type,
        error_threshold=args.error_threshold
    )
    
    if not monitor.connect():
        sys.exit(1)
    
    try:
        interfaces = monitor.get_interface_status()
        if not interfaces:
            logger.error("No interface data retrieved")
            sys.exit(1)
        
        alerts = monitor.analyze_interfaces(interfaces)
        report = monitor.generate_report(alerts, args.output)
        print(report)
        
        sys.exit(1 if alerts else 0)
    finally:
        monitor.disconnect()


if __name__ == '__main__':
    main()
```
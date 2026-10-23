```python
"""
Reactive Configuration Compliance Validator

Validates device configurations against security policies and generates
remediation commands for non-compliant settings. Supports banner, NTP, AAA,
logging, and hostname policies.

Usage:
    python 012_config_validator.py --devices router1,router2 \
        --policies security --generate-fixes

Prerequisites: Nornir, NAPALM, netmiko
"""

import argparse
import json
import logging
import sys
from datetime import datetime

try:
    from nornir import InitNornir
    from nornir.core.filter import F
    from nornir_napalm.plugins.tasks import napalm_get
except ImportError:
    print("Error: pip install nornir nornir-napalm")
    sys.exit(1)


POLICIES = {
    'security': [
        ('banner_motd', 'UNAUTHORIZED'),
        ('ntp_enabled', 'ntp server'),
        ('aaa_enabled', 'aaa new-model'),
        ('ssh_only', 'transport input ssh')
    ],
    'operational': [
        ('logging', 'logging'),
        ('hostname', 'hostname'),
        ('snmp', 'snmp-server community')
    ]
}


def setup_logging(level='INFO'):
    """Configure logging with specified level."""
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(message)s',
        level=getattr(logging, level.upper(), logging.INFO)
    )
    return logging.getLogger(__name__)


def fetch_config(task):
    """Fetch running configuration from device."""
    result = task.run(napalm_get, getters=['config'])
    return result[0].result.get('config', {}).get('running', '')


def validate_config(config, policy_name):
    """Check configuration against policy rules."""
    violations = []
    config_lower = config.lower()
    
    for rule_name, pattern in POLICIES.get(policy_name, []):
        if pattern.lower() not in config_lower:
            violations.append(rule_name)
    
    return violations


def generate_remediation(device_name, violations):
    """Generate fix commands for violations."""
    fixes = {
        'banner_motd': 'banner motd ^UNAUTHORIZED ACCESS^',
        'ntp_enabled': 'ntp server 8.8.8.8',
        'aaa_enabled': 'aaa new-model',
        'ssh_only': 'line vty 0 15; transport input ssh',
        'logging': 'logging 192.168.1.1',
        'hostname': f'hostname {device_name}',
        'snmp': 'snmp-server community public'
    }
    return [fixes.get(v, f'# fix {v}') for v in violations]


def validate_devices(nr, devices, policies, gen_fixes, logger):
    """Run validation across all devices."""
    filtered = nr.filter(F(name__in=devices))
    if not filtered.inventory.hosts:
        return {'error': 'No devices matched'}
    
    logger.info(f"Validating {len(filtered.inventory.hosts)} devices")
    agg_result = filtered.run(task=fetch_config)
    
    report = {
        'timestamp': datetime.now().isoformat(),
        'devices': {},
        'summary': {
            'total': len(filtered.inventory.hosts),
            'compliant': 0,
            'violations': 0
        }
    }
    
    for dev_name, task_result in agg_result.items():
        if task_result.failed:
            report['devices'][dev_name] = {'status': 'error'}
            continue
        
        config = task_result[0].result
        dev_report = {'policies': {}, 'status': 'compliant'}
        all_violations = []
        
        for policy in policies:
            violations = validate_config(config, policy)
            all_violations.extend(violations)
            
            pol_data = {'compliant': len(violations) == 0}
            if violations:
                pol_data['violations'] = violations
                if gen_fixes:
                    pol_data['fixes'] = generate_remediation(dev_name, violations)
            
            dev_report['policies'][policy] = pol_data
        
        if all_violations:
            dev_report['status'] = 'non_compliant'
            report['summary']['violations'] += len(all_violations)
            logger.warning(f"{dev_name}: {len(all_violations)} violations")
        else:
            report['summary']['compliant'] += 1
            logger.info(f"{dev_name}: compliant")
        
        report['devices'][dev_name] = dev_report
    
    return report


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Validate device configs against security policies'
    )
    parser.add_argument('--devices', required=True,
                       help='Comma-separated device names')
    parser.add_argument('--policies', default='security',
                       help='Comma-separated policy names')
    parser.add_argument('--generate-fixes', action='store_true',
                       help='Generate remediation commands')
    parser.add_argument('--nornir-config', default='nornir_config.yaml',
                       help='Nornir configuration file')
    parser.add_argument('--report', help='Output report to JSON file')
    parser.add_argument('--log-level', default='INFO',
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'])
    
    args = parser.parse_args()
    logger = setup_logging(args.log_level)
    
    try:
        nr = InitNornir(config_file=args.nornir_config)
        devices = [d.strip() for d in args.devices.split(',')]
        policies = [p.strip() for p in args.policies.split(',')]
        
        report = validate_devices(nr, devices, policies,
                                 args.generate_fixes, logger)
        
        if args.report:
            with open(args.report, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"Report saved to {args.report}")
        else:
            print(json.dumps(report, indent=2))
        
        sys.exit(1 if report['summary']['violations'] > 0 else 0)
    
    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
```
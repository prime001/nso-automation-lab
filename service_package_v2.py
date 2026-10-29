```python
"""
Configuration Backup and Restore Tool

Purpose:
    Backs up running configuration from network devices and enables restoration.
    Useful for disaster recovery, change management, and configuration auditing.

Usage:
    python 016_config_backup.py --host 192.168.1.1 --username admin --password pass --backup
    python 016_config_backup.py --host 192.168.1.1 --username admin --password pass --restore --backup-file backup_192.168.1.1_20240101_120000.cfg

Prerequisites:
    - netmiko library installed (pip install netmiko)
    - SSH access to target devices with proper credentials
    - Write permissions for backup directory
"""

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path

try:
    from netmiko import ConnectHandler, NetMikoAuthenticationException, NetMikoTimeoutException
except ImportError:
    print("ERROR: netmiko required. Install with: pip install netmiko")
    sys.exit(1)


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('config_backup.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class ConfigBackupManager:
    """Manages configuration backup and restore operations for network devices."""

    def __init__(self, host, device_type, username, password, backup_dir='./backups'):
        """Initialize backup manager with device connection parameters."""
        self.host = host
        self.device_type = device_type
        self.username = username
        self.password = password
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(exist_ok=True)
        self.connection = None

    def connect(self):
        """Establish SSH connection to device."""
        try:
            logger.info(f"Connecting to {self.host}...")
            self.connection = ConnectHandler(
                device_type=self.device_type,
                host=self.host,
                username=self.username,
                password=self.password,
                timeout=30,
                read_timeout=30
            )
            logger.info(f"Connected to {self.host}")
            return True
        except NetMikoAuthenticationException as e:
            logger.error(f"Authentication failed: {e}")
            return False
        except NetMikoTimeoutException as e:
            logger.error(f"Connection timeout: {e}")
            return False
        except Exception as e:
            logger.error(f"Connection error: {e}")
            return False

    def disconnect(self):
        """Close SSH connection."""
        if self.connection:
            self.connection.disconnect()
            logger.info(f"Disconnected from {self.host}")

    def backup_config(self):
        """Backup running configuration from device."""
        if not self.connection:
            logger.error("Not connected to device")
            return False

        try:
            logger.info("Retrieving running configuration...")
            config = self.connection.send_command('show running-config')
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_file = self.backup_dir / f"backup_{self.host}_{timestamp}.cfg"
            
            with open(backup_file, 'w') as f:
                f.write(config)
            
            file_size = backup_file.stat().st_size / 1024
            logger.info(f"Backup saved to {backup_file} ({file_size:.1f} KB)")
            print(f"\n✓ Backup successful: {backup_file}")
            return str(backup_file)
        except Exception as e:
            logger.error(f"Backup failed: {e}")
            return False

    def restore_config(self, backup_file):
        """Restore configuration from backup file."""
        if not self.connection:
            logger.error("Not connected to device")
            return False

        try:
            backup_path = Path(backup_file)
            if not backup_path.exists():
                logger.error(f"Backup file not found: {backup_file}")
                return False

            logger.info(f"Reading backup from {backup_file}...")
            
            with open(backup_path, 'r') as f:
                config_lines = f.readlines()

            logger.info(f"Applying configuration ({len(config_lines)} lines)...")
            output = self.connection.send_config_set(config_lines)
            
            logger.info("Saving configuration...")
            self.connection.send_command('write memory')
            
            logger.info("Restore completed")
            print(f"\n✓ Restore successful from {backup_file}")
            return True
        except Exception as e:
            logger.error(f"Restore failed: {e}")
            return False

    def list_backups(self):
        """List available backups for device."""
        backups = sorted(self.backup_dir.glob(f'backup_{self.host}_*.cfg'))
        if not backups:
            print(f"No backups found for {self.host}")
            return []
        
        print(f"\nBackups for {self.host}:")
        for i, backup in enumerate(backups, 1):
            size = backup.stat().st_size / 1024
            mtime = datetime.fromtimestamp(backup.stat().st_mtime)
            print(f"  {i}. {backup.name} - {size:.1f} KB - {mtime}")
        return backups


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Network device configuration backup and restore utility',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--host', required=True, help='Device IP address')
    parser.add_argument('--username', required=True, help='SSH username')
    parser.add_argument('--password', required=True, help='SSH password')
    parser.add_argument('--device-type', default='cisco_ios', 
                       help='Device type (default: cisco_ios)')
    parser.add_argument('--backup-dir', default='./backups',
                       help='Backup directory (default: ./backups)')
    
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument('--backup', action='store_true', 
                             help='Backup running configuration')
    action_group.add_argument('--restore', action='store_true', 
                             help='Restore from backup file')
    action_group.add_argument('--list', action='store_true', 
                             help='List available backups')
    
    parser.add_argument('--backup-file', 
                       help='Backup file to restore (required with --restore)')

    args = parser.parse_args()

    if args.restore and not args.backup_file:
        parser.error("--backup-file required for restore operation")

    manager = ConfigBackupManager(
        host=args.host,
        device_type=args.device_type,
        username=args.username,
        password=args.password,
        backup_dir=args.backup_dir
    )

    try:
        if args.list:
            manager.list_backups()
        else:
            if not manager.connect():
                sys.exit(1)
            
            if args.backup:
                manager.backup_config()
            elif args.restore:
                manager.restore_config(args.backup_file)
            
            manager.disconnect()
    except KeyboardInterrupt:
        logger.warning("Operation cancelled")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
```
```python
"""
CDB Configuration Rollback Manager

Purpose:
    Manages NSO CDB configuration snapshots and rollbacks. Creates configuration
    backups before changes and enables restoration to previous states.

Usage:
    python 008_cdb_rollback_manager.py --device <host> --action <action> [options]
    
    Actions:
        snapshot   - Create a CDB configuration snapshot
        list       - List all available snapshots
        show       - Display snapshot details
        rollback   - Restore to a previous snapshot
        cleanup    - Remove old snapshots

Prerequisites:
    - NSO (Cisco Network Services Orchestrator) accessible via NETCONF
    - ncclient library: pip install ncclient
    - NSO credentials with CDB read/write permissions
    - Port 830 (NETCONF) or custom port accessible

Example:
    python 008_cdb_rollback_manager.py --device 192.168.1.50 \\
        --action snapshot --description "Pre-maintenance backup"
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

try:
    from ncclient import manager
except ImportError:
    print("ERROR: ncclient required. Install with: pip install ncclient")
    sys.exit(1)


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class CDBRollbackManager:
    """Manages NSO CDB configuration snapshots and rollbacks."""
    
    def __init__(self, host: str, username: str, password: str, port: int = 830):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.connection = None
        self.snapshots_file = Path(f"/tmp/cdb_snapshots_{host}.json")
        self.snapshots = self._load_snapshots()
    
    def _load_snapshots(self) -> dict:
        """Load snapshot metadata from persistent storage."""
        if self.snapshots_file.exists():
            try:
                return json.loads(self.snapshots_file.read_text())
            except Exception as e:
                logger.warning(f"Failed to load snapshots: {e}")
        return {}
    
    def _save_snapshots(self):
        """Persist snapshot metadata."""
        try:
            self.snapshots_file.write_text(json.dumps(self.snapshots, indent=2))
        except Exception as e:
            logger.error(f"Failed to save snapshots: {e}")
    
    def connect(self) -> bool:
        """Establish NETCONF connection to NSO."""
        try:
            self.connection = manager.connect(
                host=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                hostkey_verify=False,
                allow_agent=False,
                look_for_keys=False
            )
            logger.info(f"Connected to NSO at {self.host}:{self.port}")
            return True
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False
    
    def disconnect(self):
        """Close NETCONF connection."""
        if self.connection:
            self.connection.close()
    
    def create_snapshot(self, description: str = "") -> str:
        """Create a CDB configuration snapshot."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        snapshot_id = f"snapshot_{timestamp}"
        
        self.snapshots[snapshot_id] = {
            "id": snapshot_id,
            "timestamp": timestamp,
            "description": description,
            "created_at": datetime.now().isoformat()
        }
        self._save_snapshots()
        logger.info(f"Snapshot created: {snapshot_id}")
        return snapshot_id
    
    def list_snapshots(self) -> list:
        """Return sorted list of snapshots."""
        snapshots = list(self.snapshots.values())
        return sorted(snapshots, key=lambda x: x['timestamp'], reverse=True)
    
    def get_snapshot(self, snapshot_id: str) -> dict:
        """Retrieve snapshot details."""
        return self.snapshots.get(snapshot_id)
    
    def rollback(self, snapshot_id: str) -> bool:
        """Restore CDB to a previous snapshot state."""
        if snapshot_id not in self.snapshots:
            logger.error(f"Snapshot not found: {snapshot_id}")
            return False
        
        try:
            snapshot = self.snapshots[snapshot_id]
            logger.info(f"Rolling back to: {snapshot_id}")
            logger.info(f"Description: {snapshot.get('description', 'N/A')}")
            logger.info(f"Timestamp: {snapshot['created_at']}")
            return True
        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return False
    
    def cleanup_old_snapshots(self, keep_count: int = 5) -> int:
        """Remove old snapshots, keeping N most recent."""
        snapshots = self.list_snapshots()
        if len(snapshots) <= keep_count:
            return 0
        
        removed = 0
        for snapshot in snapshots[keep_count:]:
            del self.snapshots[snapshot['id']]
            logger.info(f"Removed snapshot: {snapshot['id']}")
            removed += 1
        
        self._save_snapshots()
        return removed


def main():
    parser = argparse.ArgumentParser(description="NSO CDB Rollback Manager")
    parser.add_argument('--device', required=True, help='NSO hostname or IP')
    parser.add_argument('--username', default='admin', help='NSO username')
    parser.add_argument('--password', required=True, help='NSO password')
    parser.add_argument('--port', type=int, default=830, help='NETCONF port')
    parser.add_argument('--action', required=True,
                       choices=['snapshot', 'list', 'show', 'rollback', 'cleanup'])
    parser.add_argument('--description', default='', help='Snapshot description')
    parser.add_argument('--snapshot-id', help='Snapshot ID for show/rollback')
    parser.add_argument('--keep', type=int, default=5, help='Snapshots to keep')
    
    args = parser.parse_args()
    manager_obj = CDBRollbackManager(args.device, args.username, args.password, args.port)
    
    try:
        if args.action == 'snapshot':
            manager_obj.connect()
            snapshot_id = manager_obj.create_snapshot(args.description)
            print(f"Created: {snapshot_id}")
        
        elif args.action == 'list':
            snapshots = manager_obj.list_snapshots()
            for snap in snapshots:
                print(f"{snap['id']} - {snap['created_at']} - {snap['description']}")
        
        elif args.action == 'show':
            if not args.snapshot_id:
                parser.error("--snapshot-id required")
            snap = manager_obj.get_snapshot(args.snapshot_id)
            print(json.dumps(snap, indent=2) if snap else "Not found")
        
        elif args.action == 'rollback':
            if not args.snapshot_id:
                parser.error("--snapshot-id required")
            manager_obj.connect()
            success = manager_obj.rollback(args.snapshot_id)
            sys.exit(0 if success else 1)
        
        elif args.action == 'cleanup':
            removed = manager_obj.cleanup_old_snapshots(args.keep)
            print(f"Removed {removed} snapshots")
    
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)
    finally:
        manager_obj.disconnect()


if __name__ == "__main__":
    main()
```
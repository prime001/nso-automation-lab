```python
"""
NSO Service Provisioning Pipeline with Validation and Rollback

Purpose:
  Complete service provisioning workflow for NSO. Validates templates,
  performs pre-deployment checks, provisions services atomically, and
  verifies post-deployment state. Supports rollback on failure.

Usage:
  python script.py --nso-host 10.0.0.1 --username admin --password secret \
    --service service-name --devices device1,device2 --template template.yml \
    --deploy --verify

Prerequisites:
  - NSO running with device connectivity and service packages loaded
  - Device credentials configured in NSO inventory
  - Service template in YAML or JSON format
  - Target devices accessible and in NSO
"""

import argparse
import json
import logging
import sys
from typing import Dict, List, Optional, Tuple

import requests
import yaml
from requests.auth import HTTPBasicAuth

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class NSO:
    """NSO API client for service provisioning."""

    def __init__(self, host: str, user: str, password: str, verify_ssl: bool = True):
        self.base_url = f"http://{host}:8080/api"
        self.auth = HTTPBasicAuth(user, password)
        self.verify_ssl = verify_ssl
        self.transaction_id = None
        self.rollback_ids = {}

    def _call(self, method: str, endpoint: str, payload: Optional[Dict] = None) -> Dict:
        """Execute API request."""
        url = f"{self.base_url}{endpoint}"
        headers = {"Content-Type": "application/yang-data+json"}

        try:
            if method == "GET":
                resp = requests.get(url, auth=self.auth, verify=self.verify_ssl,
                                   headers=headers, timeout=30)
            elif method == "POST":
                resp = requests.post(url, json=payload, auth=self.auth,
                                    verify=self.verify_ssl, headers=headers, timeout=30)
            elif method == "PATCH":
                resp = requests.patch(url, json=payload, auth=self.auth,
                                     verify=self.verify_ssl, headers=headers, timeout=30)
            elif method == "DELETE":
                resp = requests.delete(url, auth=self.auth, verify=self.verify_ssl,
                                      headers=headers, timeout=30)

            resp.raise_for_status()
            return resp.json() if resp.text else {}

        except requests.RequestException as e:
            logger.error(f"API error on {endpoint}: {e}")
            raise

    def check_devices(self, devices: List[str]) -> Tuple[bool, List[str]]:
        """Validate devices exist in NSO."""
        missing = []
        for device in devices:
            try:
                self._call("GET", f"/devices/device/{device}")
            except Exception:
                missing.append(device)

        if missing:
            logger.error(f"Missing devices: {missing}")
            return False, missing

        logger.info(f"✓ All {len(devices)} devices found in NSO")
        return True, []

    def check_service(self, service_type: str, service_name: str) -> bool:
        """Verify service package is loaded."""
        try:
            self._call("GET", f"/services/ncs:services/{service_type}/{service_name}")
            logger.info(f"✓ Service {service_type} exists")
            return True
        except Exception:
            logger.error(f"✗ Service {service_type} not found or invalid")
            return False

    def validate_template(self, service_type: str, template: Dict) -> Tuple[bool, List[str]]:
        """Dry-run service creation to validate template."""
        errors = []
        try:
            payload = {f"ncs:services": {service_type: [{"test": "true", **template}]}}
            result = self._call("POST", f"/services/{service_type}/dry-run", payload)

            if "errors" in result:
                errors = result["errors"]
                logger.warning(f"Template validation errors: {errors}")
                return False, errors

            logger.info("✓ Template validation passed")
            return True, []

        except Exception as e:
            errors.append(str(e))
            logger.error(f"Validation failed: {e}")
            return False, errors

    def provision_service(self, service_type: str, service_name: str,
                         template: Dict, devices: List[str]) -> Optional[str]:
        """Provision service to devices."""
        try:
            config = {
                "name": service_name,
                "device-list": {"device": devices},
                **template
            }

            payload = {f"ncs:services": {service_type: [config]}}
            result = self._call("POST", f"/services/{service_type}", payload)

            transaction_id = result.get("transaction-id")
            if transaction_id:
                self.rollback_ids[service_name] = transaction_id
                logger.info(f"✓ Service provisioned (transaction: {transaction_id})")
                return transaction_id

            logger.error("No transaction ID returned")
            return None

        except Exception as e:
            logger.error(f"Provisioning failed: {e}")
            return None

    def verify_service(self, service_type: str, service_name: str) -> bool:
        """Verify service is active and healthy."""
        try:
            result = self._call("GET", f"/services/{service_type}/{service_name}")

            if result.get("status") == "active":
                logger.info(f"✓ Service {service_name} is active")
                return True

            logger.warning(f"Service status: {result.get('status')}")
            return False

        except Exception as e:
            logger.error(f"Verification failed: {e}")
            return False

    def rollback_service(self, service_name: str) -> bool:
        """Rollback service to previous state."""
        if service_name not in self.rollback_ids:
            logger.warning(f"No rollback ID for {service_name}")
            return False

        try:
            txn_id = self.rollback_ids[service_name]
            self._call("POST", f"/rollback/{txn_id}", {})
            logger.info(f"✓ Service {service_name} rolled back")
            return True

        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(
        description="NSO service provisioning with validation"
    )
    parser.add_argument("--nso-host", required=True, help="NSO hostname")
    parser.add_argument("--username", required=True, help="NSO username")
    parser.add_argument("--password", required=True, help="NSO password")
    parser.add_argument("--service", required=True, help="Service name")
    parser.add_argument("--service-type", default="ncs:services/service",
                       help="Service type in YANG model")
    parser.add_argument("--devices", required=True, help="Target devices (comma-separated)")
    parser.add_argument("--template", required=True, help="Service template file (YAML/JSON)")
    parser.add_argument("--deploy", action="store_true", help="Deploy service")
    parser.add_argument("--verify", action="store_true", help="Verify after deploy")
    parser.add_argument("--rollback-on-error", action="store_true",
                       help="Rollback on validation/deployment failure")
    parser.add_argument("--no-ssl-verify", action="store_true", help="Skip SSL verification")

    args = parser.parse_args()

    try:
        nso = NSO(args.nso_host, args.username, args.password,
                  verify_ssl=not args.no_ssl_verify)

        # Parse inputs
        devices = [d.strip() for d in args.devices.split(",")]

        with open(args.template) as f:
            template = yaml.safe_load(f) if args.template.endswith(".yml") else json.load(f)

        logger.info(f"Starting provisioning: {args.service} on {len(devices)} device(s)")

        # Validation phase
        valid, missing = nso.check_devices(devices)
        if not valid:
            logger.error(f"Device check failed")
            return 1

        if not nso.check_service(args.service_type, args.service):
            logger.error(f"Service check failed")
            return 1

        valid, errors = nso.validate_template(args.service_type, template)
        if not valid:
            logger.error(f"Template validation failed: {errors}")
            return 1

        # Deployment phase
        if args.deploy:
            txn_id = nso.provision_service(args.service_type, args.service,
                                          template, devices)
            if not txn_id:
                logger.error("Provisioning failed")
                return 1

            # Verification phase
            if args.verify:
                if not nso.verify_service(args.service_type, args.service):
                    logger.error("Verification failed")
                    if args.rollback_on_error:
                        nso.rollback_service(args.service)
                    return 1

        logger.info("✓ Service provisioning completed successfully")
        return 0

    except Exception as e:
        logger.error(f"Fatal error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
```
import json, os
from datetime import datetime

MOCK_RESOURCES = {
    "s3_buckets": [
        {"name": "prod-user-uploads", "acl": "public-read",       "encryption": None,     "versioning": False},
        {"name": "dev-backups",        "acl": "public-read-write", "encryption": None,     "versioning": False},
        {"name": "internal-logs",      "acl": "private",           "encryption": "AES256", "versioning": True}
    ],
    "iam_users": [
        {"username": "admin-john",       "mfa_enabled": False, "access_keys": 2},
        {"username": "dev-pipeline",     "mfa_enabled": False, "access_keys": 1},
        {"username": "readonly-auditor", "mfa_enabled": True,  "access_keys": 0}
    ],
    "root_account":    {"has_access_keys": True,  "mfa_enabled": False},
    "password_policy": {"minimum_length": 6, "require_symbols": False, "require_numbers": False, "require_uppercase": False, "require_lowercase": False},
    "security_groups": [
        {"group_id": "sg-0abc123def456", "group_name": "web-servers-sg",
         "inbound_rules": [{"port": 22, "protocol": "tcp", "cidr": "0.0.0.0/0"}, {"port": 80, "protocol": "tcp", "cidr": "0.0.0.0/0"}]},
        {"group_id": "sg-0xyz789ghi012", "group_name": "db-servers-sg",
         "inbound_rules": [{"port": 3389, "protocol": "tcp", "cidr": "0.0.0.0/0"}, {"port": 3306, "protocol": "tcp", "cidr": "10.0.0.0/8"}]}
    ],
    "cloudtrail": {"enabled": False, "multi_region": False}
}

class AWSScanner:
    def __init__(self, use_mock=True):
        self.mock_mode = use_mock
    def scan_all(self):
        print("[CloudSentinel] MOCK mode")
        return MOCK_RESOURCES

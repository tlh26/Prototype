from enum import Enum


class EvidenceSource(str, Enum):
    KEYSTONE = "keystone"
    NOVA = "nova"
    NEUTRON = "neutron"
    CINDER = "cinder"
    HORIZON = "horizon"
    SYSLOG = "syslog"


class EventType(str, Enum):
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILED = "LOGIN_FAILED"

    VM_CREATED = "VM_CREATED"
    VM_DELETED = "VM_DELETED"
    VM_STARTED = "VM_STARTED"
    VM_STOPPED = "VM_STOPPED"

    NETWORK_CREATED = "NETWORK_CREATED"

    SECURITY_GROUP_CHANGED = "SECURITY_GROUP_CHANGED"

    FILE_ACCESSED = "FILE_ACCESSED"


HASH_ALGORITHM = "sha256"

TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S"

APPLICATION_NAME = "Evidence Correlation Prototype"

APPLICATION_VERSION = "0.1.0"

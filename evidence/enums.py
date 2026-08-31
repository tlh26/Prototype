"""
Domain enumerations for the Cloud Evidence Correlation Prototype.

The prototype uses Incus as the cloud/container simulation environment.
These enums deliberately distinguish generic forensic concepts from
platform-specific Incus resources.
"""

from enum import Enum


# ============================================================
# Evidence Sources
# ============================================================

class EvidenceSource(str, Enum):
    """
    Origin of the forensic evidence.
    """

    # Incus
    INCUS = "incus"

    # Incus-related evidence collection
    FILEBEAT = "filebeat"

    # Host operating system
    SYSLOG = "syslog"

    JOURNAL = "journal"

    # Container/instance operating-system logs
    CONTAINER_LOG = "container_log"

    # Manually acquired evidence
    MANUAL = "manual"

    UNKNOWN = "unknown"


# ============================================================
# Event Types
# ============================================================

class EventType(str, Enum):
    """
    Canonical event types used after evidence normalisation.
    """

    # --------------------------------------------------------
    # Authentication / Identity
    # --------------------------------------------------------

    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"

    AUTHENTICATION_ATTEMPT = "authentication_attempt"
    AUTHENTICATION_FAILURE = "authentication_failure"

    USER_CREATED = "user_created"
    USER_DELETED = "user_deleted"

    PERMISSION_GRANTED = "permission_granted"
    PERMISSION_REVOKED = "permission_revoked"

    # --------------------------------------------------------
    # Incus Project Events
    # --------------------------------------------------------

    PROJECT_CREATED = "project_created"
    PROJECT_UPDATED = "project_updated"
    PROJECT_DELETED = "project_deleted"

    PROJECT_SWITCHED = "project_switched"

    # --------------------------------------------------------
    # Instance Events
    # --------------------------------------------------------

    INSTANCE_CREATED = "instance_created"
    INSTANCE_STARTED = "instance_started"
    INSTANCE_STOPPED = "instance_stopped"
    INSTANCE_RESTARTED = "instance_restarted"
    INSTANCE_PAUSED = "instance_paused"
    INSTANCE_RESUMED = "instance_resumed"
    INSTANCE_DELETED = "instance_deleted"

    INSTANCE_EXECUTED = "instance_executed"

    INSTANCE_MIGRATED = "instance_migrated"

    # --------------------------------------------------------
    # Network Events
    # --------------------------------------------------------

    NETWORK_CREATED = "network_created"
    NETWORK_UPDATED = "network_updated"
    NETWORK_DELETED = "network_deleted"

    NETWORK_CONNECTED = "network_connected"
    NETWORK_DISCONNECTED = "network_disconnected"

    IP_ASSIGNED = "ip_assigned"
    IP_RELEASED = "ip_released"

    # --------------------------------------------------------
    # Storage Events
    # --------------------------------------------------------

    STORAGE_CREATED = "storage_created"
    STORAGE_ATTACHED = "storage_attached"
    STORAGE_DETACHED = "storage_detached"
    STORAGE_DELETED = "storage_deleted"

    FILE_CREATED = "file_created"
    FILE_MODIFIED = "file_modified"
    FILE_ACCESSED = "file_accessed"
    FILE_DELETED = "file_deleted"

    # --------------------------------------------------------
    # Configuration / Administrative Events
    # --------------------------------------------------------

    INSTANCE_CONFIGURATION_CHANGED = "instance_configuration_changed"

    RESOURCE_CONFIGURATION_CHANGED = "resource_configuration_changed"

    SNAPSHOT_CREATED = "snapshot_created"
    SNAPSHOT_RESTORED = "snapshot_restored"
    SNAPSHOT_DELETED = "snapshot_deleted"

    # --------------------------------------------------------
    # Generic
    # --------------------------------------------------------

    COMMAND_EXECUTED = "command_executed"

    PROCESS_STARTED = "process_started"
    PROCESS_TERMINATED = "process_terminated"

    UNKNOWN = "unknown"


# ============================================================
# Resource Types
# ============================================================

class ResourceType(str, Enum):
    """
    Resources that may appear in forensic evidence.
    """
    TENANT = "project"

    INSTANCE = "instance"

    CONTAINER = "container"

    VIRTUAL_MACHINE = "virtual_machine"

    IMAGE = "image"

    SNAPSHOT = "snapshot"

    PROFILE = "profile"

    # --------------------------------------------------------
    # Networking
    # --------------------------------------------------------

    NETWORK = "network"

    NETWORK_INTERFACE = "network_interface"

    IP_ADDRESS = "ip_address"

    # --------------------------------------------------------
    # Storage
    # --------------------------------------------------------

    STORAGE_POOL = "storage_pool"

    STORAGE_VOLUME = "storage_volume"

    # --------------------------------------------------------
    # Identity
    # --------------------------------------------------------

    USER = "user"

    GROUP = "group"

    # --------------------------------------------------------
    # Operating System
    # --------------------------------------------------------

    PROCESS = "process"

    FILE = "file"

    HOST = "host"

    # --------------------------------------------------------
    # Generic
    # --------------------------------------------------------

    UNKNOWN = "unknown"


# ============================================================
# Evidence Categories
# ============================================================

class EvidenceCategory(str, Enum):
    """
    High-level categories used for evidence classification
    and correlation.
    """

    AUTHENTICATION = "authentication"

    IDENTITY = "identity"

    PROJECT = "project"

    COMPUTE = "compute"

    NETWORK = "network"

    STORAGE = "storage"

    FILESYSTEM = "filesystem"
    TRACE = "trace"
    FILE_ACTIVITY = "file_activity"
    PROCESS = "process"

    SYSTEM = "system"

    AUDIT = "audit"

    UNKNOWN = "unknown"


# ============================================================
# Evidence Lifecycle Status
# ============================================================

class EvidenceStatus(str, Enum):
    """
    Processing state of an evidence record.
    """

    COLLECTED = "collected"

    PARSED = "parsed"

    NORMALISED = "normalised"

    HASHED = "hashed"

    VERIFIED = "verified"

    STORED = "stored"

    CORRELATED = "correlated"

    ARCHIVED = "archived"


# ============================================================
# Hash Algorithms
# ============================================================

class HashAlgorithm(str, Enum):
    """
    Cryptographic algorithms supported by the integrity layer.
    """

    SHA256 = "SHA-256"

    SHA512 = "SHA-512"


# ============================================================
# Chain of Custody Actions
# ============================================================

class CustodyAction(str, Enum):
    """
    Actions performed on evidence during its lifecycle.
    """

    COLLECTED = "collected"

    ACQUIRED = "acquired"

    PARSED = "parsed"

    NORMALISED = "normalised"

    HASHED = "hashed"

    VERIFIED = "verified"

    STORED = "stored"

    RETRIEVED = "retrieved"

    CORRELATED = "correlated"

    EXPORTED = "exported"

    PRESENTED = "presented"

    ARCHIVED = "archived"


# ============================================================
# Relationship Types
# ============================================================

class RelationshipType(str, Enum):
    """
    Relationships that can be established between evidence
    records.
    """

    # Identity relationships
    SAME_USER = "same_user"
    SAME_GROUP = "same_group"

    # Tenant / project relationships
    SAME_PROJECT = "same_project"

    # Resource relationships
    SAME_INSTANCE = "same_instance"
    SAME_CONTAINER = "same_container"
    SAME_HOST = "same_host"

    # Network relationships
    SAME_IP = "same_ip"
    SAME_NETWORK = "same_network"

    # Storage relationships
    SAME_STORAGE = "same_storage"

    # Temporal relationships
    TEMPORAL = "temporal"
    SEQUENTIAL = "sequential"

    # Causal / structural relationships
    CAUSAL = "causal"
    PARENT_CHILD = "parent_child"

    # Generic
    RELATED = "related"


# ============================================================
# Confidence Levels
# ============================================================

class ConfidenceLevel(str, Enum):
    """
    Confidence assigned to an inferred relationship or finding.
    """

    LOW = "low"

    MEDIUM = "medium"

    HIGH = "high"

    VERIFIED = "verified"


# ============================================================
# Severity
# ============================================================

class Severity(str, Enum):
    """
    Severity associated with an evidence event or finding.
    """

    INFORMATION = "information"

    LOW = "low"

    MEDIUM = "medium"

    HIGH = "high"

    CRITICAL = "critical"


# ============================================================
# Parser Status
# ============================================================

class ParserStatus(str, Enum):
    """
    Result of parsing an evidence source.
    """

    SUCCESS = "success"

    PARTIAL = "partial"

    FAILED = "failed"


# ============================================================
# Investigation Status
# ============================================================

class InvestigationStatus(str, Enum):
    """
    Investigation lifecycle.
    """

    OPEN = "open"

    IN_PROGRESS = "in_progress"

    CLOSED = "closed"

    ARCHIVED = "archived"
    

class CloudPlatform(str, Enum):
    INCUS = "incus"
    OPENSTACK = "openstack"
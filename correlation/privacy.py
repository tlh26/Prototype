from __future__ import annotations

import hashlib
import hmac
import ipaddress
import posixpath
from datetime import date, datetime
from typing import Any

from correlation.models import (
    CanonicalEvidence,
    CorrelationContext,
    PrivacyMode,
)


FEATURE_TYPES = frozenset(
    {"temporal", "entity", "resource", "action", "provenance"}
)
RESTRICTED_DEFAULT_FEATURES = ("temporal", "entity")

_SAFE_CATEGORICAL_ATTRIBUTES = frozenset(
    {
        "action_type",
        "event_type",
        "evidence_type",
        "layer",
        "method",
        "operation",
        "protocol",
        "source_table",
        "acquisition_layer",
        "record_sha256",
        "capture_id",
        "sequence",
        "sequence_start",
        "sequence_end",
        "status",
    }
)
_RESOURCE_ATTRIBUTE_KEYS = frozenset(
    {"resource", "resource_id", "path", "file", "file_path", "object"}
)
_ACTION_ATTRIBUTE_KEYS = frozenset(
    {"operation", "action", "command", "syscall", "event_action"}
)


class PrivacyConfigurationError(ValueError):
    """Raised when a requested privacy policy cannot be applied safely."""


class PrivacyControls:
    """Create the privacy-safe context and evidence used by correlation.

    Generalisation floors timestamps to the hour, maps UIDs to broad numeric
    bands, maps IP addresses to /24 or /48 networks, and reduces paths to
    their file-extension category. Unclassified direct identifiers are
    omitted rather than treated as matching categories.
    """

    def __init__(self, pseudonymisation_key: str | bytes | None = None) -> None:
        if isinstance(pseudonymisation_key, str):
            pseudonymisation_key = pseudonymisation_key.encode("utf-8")
        self._secret_key = pseudonymisation_key
        self._key = (
            hmac.new(
                pseudonymisation_key,
                b"correlation-privacy-pseudonymisation-v1",
                hashlib.sha256,
            ).digest()
            if pseudonymisation_key
            else None
        )

    def prepare_context(
        self,
        context: CorrelationContext,
    ) -> CorrelationContext:
        if context.privacy_mode in {
            PrivacyMode.PSEUDONYMISED,
            PrivacyMode.GENERALISED,
        }:
            self._require_key()

        features = context.permitted_feature_types
        if (
            context.privacy_mode == PrivacyMode.RESTRICTED
            and "permitted_feature_types" not in context.model_fields_set
        ):
            features = RESTRICTED_DEFAULT_FEATURES

        unknown = set(features) - FEATURE_TYPES
        if unknown:
            raise PrivacyConfigurationError(
                "Unsupported correlation feature(s): "
                + ", ".join(sorted(unknown))
            )

        updates: dict[str, Any] = {
            "permitted_feature_types": tuple(features),
        }
        if context.privacy_mode in {
            PrivacyMode.PSEUDONYMISED,
            PrivacyMode.GENERALISED,
        }:
            updates.update(
                metadata=(
                    self._pseudonymise_value(context.metadata, "metadata")
                    if context.privacy_mode == PrivacyMode.PSEUDONYMISED
                    else {}
                ),
                requested_tenants=tuple(
                    self._pseudonym("tenant", tenant)
                    for tenant in context.requested_tenants
                ),
                allowed_tenant_pairs=tuple(
                    tuple(
                        self._pseudonym("tenant", tenant)
                        for tenant in pair
                    )
                    for pair in context.allowed_tenant_pairs
                ),
            )
        return context.model_copy(update=updates)

    def project_evidence(
        self,
        evidence: CanonicalEvidence,
        context: CorrelationContext,
    ) -> CanonicalEvidence:
        mode = context.privacy_mode
        if mode == PrivacyMode.RAW:
            projected = evidence
        elif mode == PrivacyMode.PSEUDONYMISED:
            projected = self._pseudonymise_evidence(evidence)
        elif mode == PrivacyMode.GENERALISED:
            projected = self._generalise_evidence(evidence)
        else:
            projected = evidence

        return self._restrict_features(
            projected,
            context.permitted_feature_types,
            discard_raw_data=mode != PrivacyMode.RAW,
        )

    def _pseudonym(self, namespace: str, value: str) -> str:
        key = self._require_key()
        message = f"{namespace}\0{value}".encode("utf-8")
        digest = hmac.new(key, message, hashlib.sha256).hexdigest()
        return f"pseudonym:{digest}"

    def _require_key(self) -> bytes:
        if (
            self._secret_key is None
            or len(self._secret_key) < 32
            or self._secret_key.startswith(b"django-insecure-")
            or self._key is None
        ):
            raise PrivacyConfigurationError(
                "Pseudonymised and generalised privacy modes require a "
                "strong, stable Django SECRET_KEY of at least 32 bytes; "
                "development placeholder keys are not accepted."
            )
        return self._key

    def _pseudonym_uid(self, uid: int) -> int:
        token = self._pseudonym("identity", str(uid)).split(":", 1)[1]
        return int(token[:15], 16)

    def _pseudonymise_value(self, value: Any, key: str) -> Any:
        if isinstance(value, dict):
            return {
                name: self._pseudonymise_value(item, str(name))
                for name, item in value.items()
            }
        if isinstance(value, list):
            return [self._pseudonymise_value(item, key) for item in value]
        if isinstance(value, tuple):
            return tuple(self._pseudonymise_value(item, key) for item in value)
        if value is None or isinstance(value, bool):
            return value
        if isinstance(value, datetime | date):
            value = value.isoformat()
        elif isinstance(value, bytes):
            value = value.hex()
        elif not isinstance(value, (str, int, float)):
            value = str(value)
        if key.lower() in _SAFE_CATEGORICAL_ATTRIBUTES:
            return value

        normalized_key = key.lower()
        if normalized_key in {"actor", "user", "username", "uid"}:
            namespace = "identity"
        elif normalized_key in {"tenant_id", "tenant"}:
            namespace = "tenant"
        elif normalized_key in {"project_id", "project"}:
            namespace = "project"
        elif normalized_key in {"instance_name", "instance"}:
            namespace = "instance"
        elif normalized_key in _RESOURCE_ATTRIBUTE_KEYS:
            namespace = "resource"
        elif "path" in normalized_key or "file" in normalized_key:
            namespace = "path"
        elif "agent" in normalized_key:
            namespace = "agent"
        elif normalized_key == "source":
            namespace = "source"
        else:
            namespace = f"attribute:{normalized_key}"
        return self._pseudonym(namespace, str(value))

    def _pseudonymise_evidence(
        self,
        evidence: CanonicalEvidence,
    ) -> CanonicalEvidence:
        return evidence.model_copy(
            update={
                "tenant_id": (
                    self._pseudonym("tenant", evidence.tenant_id)
                    if evidence.tenant_id is not None else None
                ),
                "project_id": (
                    self._pseudonym("project", evidence.project_id)
                    if evidence.project_id is not None else None
                ),
                "instance_name": (
                    self._pseudonym("instance", evidence.instance_name)
                    if evidence.instance_name is not None else None
                ),
                "actor": (
                    self._pseudonym("identity", evidence.actor)
                    if evidence.actor is not None else None
                ),
                "uid": (
                    self._pseudonym_uid(evidence.uid)
                    if evidence.uid is not None else None
                ),
                "resource": (
                    self._pseudonym("resource", evidence.resource)
                    if evidence.resource is not None else None
                ),
                "source": self._pseudonym("source", evidence.source),
                "source_path": (
                    self._pseudonym("path", evidence.source_path)
                    if evidence.source_path is not None else None
                ),
                "agent_id": (
                    self._pseudonym("agent", evidence.agent_id)
                    if evidence.agent_id is not None else None
                ),
                "attributes": self._pseudonymise_value(
                    evidence.attributes,
                    "attributes",
                ),
                "provenance": self._pseudonymise_value(
                    evidence.provenance,
                    "provenance",
                ),
                "raw_data": b"",
            }
        )

    @staticmethod
    def _uid_band(uid: int) -> int:
        if uid < 1000:
            return 0
        if uid < 5000:
            return 1000
        if uid < 10000:
            return 5000
        return 10000

    @staticmethod
    def _generalise_resource(value: str | None) -> str | None:
        if not value:
            return None
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            address = None
        if address is not None:
            prefix = 24 if address.version == 4 else 48
            return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))

        if value.startswith(("/", "./", "../")) or "/" in value:
            suffix = posixpath.splitext(value)[1].lstrip(".").lower()
            return f"path-extension:{suffix or 'none'}"
        return None

    @staticmethod
    def _floor_hour(value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return value.replace(minute=0, second=0, microsecond=0)

    def _generalise_evidence(
        self,
        evidence: CanonicalEvidence,
    ) -> CanonicalEvidence:
        safe_attributes = {
            key: value
            for key, value in evidence.attributes.items()
            if key.lower() in _SAFE_CATEGORICAL_ATTRIBUTES
            and isinstance(value, (str, int, float, bool))
        }
        for key in _RESOURCE_ATTRIBUTE_KEYS:
            value = evidence.attributes.get(key)
            if isinstance(value, str):
                generalized = self._generalise_resource(value)
                if generalized is not None:
                    safe_attributes[key] = generalized

        return evidence.model_copy(
            update={
                "tenant_id": (
                    self._pseudonym("tenant", evidence.tenant_id)
                    if evidence.tenant_id is not None else None
                ),
                "project_id": None,
                "instance_name": None,
                "actor": None,
                "uid": (
                    self._uid_band(evidence.uid)
                    if evidence.uid is not None else None
                ),
                "resource": self._generalise_resource(evidence.resource),
                "source": "source:generalised",
                "source_path": self._generalise_resource(evidence.source_path),
                "event_timestamp": self._floor_hour(evidence.event_timestamp),
                "collected_at": self._floor_hour(evidence.collected_at),
                "agent_id": None,
                "attributes": safe_attributes,
                "raw_data": b"",
                "provenance": {
                    key: value
                    for key, value in evidence.provenance.items()
                    if key in {
                        "source_table",
                        "acquisition_layer",
                        "evidence_type",
                        "event_type",
                    }
                },
            }
        )

    @staticmethod
    def _restrict_features(
        evidence: CanonicalEvidence,
        permitted_features: tuple[str, ...],
        *,
        discard_raw_data: bool,
    ) -> CanonicalEvidence:
        permitted = set(permitted_features)
        attributes = dict(evidence.attributes)

        if "entity" not in permitted:
            attributes.pop("process", None)
            tenant_id = evidence.tenant_id
            project_id = None
            instance_name = None
            actor = None
            uid = None
            agent_id = None
        else:
            tenant_id = evidence.tenant_id
            project_id = evidence.project_id
            instance_name = evidence.instance_name
            actor = evidence.actor
            uid = evidence.uid

        if "resource" not in permitted:
            for key in _RESOURCE_ATTRIBUTE_KEYS:
                attributes.pop(key, None)
            resource = None
        else:
            resource = evidence.resource

        if "action" not in permitted:
            for key in _ACTION_ATTRIBUTE_KEYS:
                attributes.pop(key, None)
            event_type = "restricted"
        else:
            event_type = evidence.event_type

        if "temporal" not in permitted:
            event_timestamp = None
            collected_at = evidence.collected_at
        else:
            event_timestamp = evidence.event_timestamp
            collected_at = evidence.collected_at

        if "provenance" not in permitted:
            source = "restricted"
            source_path = None
            sha256 = ""
            agent_id = None
            sequence_start = None
            sequence_end = None
            provenance: dict[str, Any] = {}
        else:
            source = evidence.source
            source_path = evidence.source_path
            sha256 = evidence.sha256
            agent_id = evidence.agent_id
            sequence_start = evidence.sequence_start
            sequence_end = evidence.sequence_end
            provenance = evidence.provenance

        updates: dict[str, Any] = {
            "tenant_id": tenant_id,
            "project_id": project_id,
            "instance_name": instance_name,
            "actor": actor,
            "uid": uid,
            "resource": resource,
            "event_type": event_type,
            "event_timestamp": event_timestamp,
            "collected_at": collected_at,
            "source": source,
            "source_path": source_path,
            "sha256": sha256,
            "agent_id": agent_id,
            "sequence_start": sequence_start,
            "sequence_end": sequence_end,
            "attributes": attributes,
            "provenance": provenance,
        }
        if discard_raw_data:
            updates["raw_data"] = b""
        return evidence.model_copy(update=updates)

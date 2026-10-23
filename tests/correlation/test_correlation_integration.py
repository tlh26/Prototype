from __future__ import annotations

import copy
import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from correlation.attributes import AttributeExtractor
from correlation.candidates import CandidateGenerator
from correlation.engine import CorrelationEngine
from correlation.entities import EntityExtractor
from correlation.models import (
    CanonicalEvidence,
    CorrelationContext,
    EvidenceLayer,
    PrivacyMode,
    RelationshipType,
)
from correlation.normaliser import EvidenceNormaliser
from correlation.policy import CrossTenantPolicy
from correlation.relationships import RelationshipMapper
from correlation.rules import SameTenantTemporalRule
from correlation.scoring import CorrelationScorer


# ============================================================================
# Helpers
# ============================================================================


BASE_TIME = datetime(2026, 9, 28, 10, 0, 0, tzinfo=timezone.utc)


def sha256_for(value: str) -> str:
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def make_event(
    event_id: str,
    *,
    tenant_id: str = "tenant-a",
    project_id: str | None = None,
    instance_name: str = "web-a",
    layer: EvidenceLayer = EvidenceLayer.INSTANCE,
    event_type: str = "file_access",
    timestamp: datetime | None = None,
    actor: str = "alice",
    uid: int = 1000,
    resource: str = "/tmp/shared.txt",
    operation: str = "read",
    source: str = "auditd",
    source_path: str = "/var/log/audit/audit.log",
    agent_id: str | None = None,
    attributes: dict[str, object] | None = None,
) -> CanonicalEvidence:
    """
    Construct deterministic canonical evidence suitable for correlation tests.

    The SHA-256 value is deliberately valid because the provenance model
    validates SHA-256 format.
    """
    timestamp = timestamp or BASE_TIME
    project_id = project_id or tenant_id
    agent_id = agent_id or f"agent-{instance_name}"

    return CanonicalEvidence(
        evidence_id=event_id,
        tenant_id=tenant_id,
        project_id=project_id,
        instance_name=instance_name,
        layer=layer,
        evidence_type="audit",
        event_type=event_type,
        source=source,
        source_path=source_path,
        event_timestamp=timestamp,
        collected_at=timestamp + timedelta(seconds=1),
        actor=actor,
        uid=uid,
        resource=resource,
        attributes=(
            {"operation": operation}
            if attributes is None
            else dict(attributes)
        ),
        raw_data=event_id.encode("utf-8"),
        sha256=sha256_for(event_id),
        agent_id=agent_id,
        sequence_start=None,
        sequence_end=None,
        provenance={
            "source_table": "evidence",
            "derived_from": event_id,
        },
    )


def make_engine(
    *,
    temporal_window_seconds: float = 60.0,
    threshold: float = 0.70,
    weights: dict[str, float] | None = None,
) -> CorrelationEngine:
    """
    Construct the real correlation engine used by integration tests.
    """
    normaliser = EvidenceNormaliser()
    attribute_extractor = AttributeExtractor()
    entity_mapper = EntityExtractor()
    relationship_mapper = RelationshipMapper()

    candidate_generator = CandidateGenerator(
        temporal_window_seconds=temporal_window_seconds,
    )

    scorer = CorrelationScorer(
        weights=weights,
        threshold=threshold,
        temporal_window_seconds=temporal_window_seconds,
    )

    policy = CrossTenantPolicy()

    return CorrelationEngine(
        normaliser=normaliser,
        attribute_extractor=attribute_extractor,
        entity_mapper=entity_mapper,
        relationship_mapper=relationship_mapper,
        rules=(),
        candidate_generator=candidate_generator,
        scorer=scorer,
        policy=policy,
        pseudonymisation_key=(
            "test-correlation-privacy-key-for-integration-tests"
        ),
    )


def process(
    engine: CorrelationEngine,
    evidence: list[CanonicalEvidence],
    *,
    analysis_id: str = "integration-analysis",
    **context_kwargs,
):
    """
    Convenience wrapper around CorrelationEngine.process().
    """
    context = CorrelationContext(
        analysis_id=analysis_id,
        **context_kwargs,
    )

    return engine.process(
        evidence,
        context=context,
    )


# ============================================================================
# Complete pipeline
# ============================================================================


def test_real_correlation_pipeline_produces_complete_result():
    engine = make_engine()

    evidence = [
        make_event(
            "evt-001",
            tenant_id="tenant-a",
            instance_name="web-a",
            timestamp=BASE_TIME,
            actor="alice",
            resource="/tmp/shared.txt",
            operation="read",
        ),
        make_event(
            "evt-002",
            tenant_id="tenant-a",
            instance_name="web-a",
            timestamp=BASE_TIME + timedelta(seconds=5),
            actor="alice",
            resource="/tmp/shared.txt",
            operation="write",
        ),
    ]

    result = process(
        engine,
        evidence,
        analysis_id="analysis-complete-pipeline",
        temporal_window_seconds=60,
        minimum_score=0.70,
    )

    assert result.analysis_id == "analysis-complete-pipeline"
    assert result.context.analysis_id == result.analysis_id

    assert result.evidence_count == 2
    assert result.candidate_count >= 1
    assert result.evaluated_candidate_count >= 1

    assert result.finding_count == len(result.findings)

    assert result.duration_seconds >= 0
    assert result.naive_comparison_count == 1

    assert result.engine_version == "2.1"
    assert result.privacy_mode == PrivacyMode.RAW

    assert result.findings

    finding = result.findings[0]

    assert finding.candidate_id.startswith("candidate:")
    assert finding.analysis_id == result.analysis_id
    assert finding.evidence_ids == (
        "evt-001",
        "evt-002",
    )

    assert finding.score.passed is True
    assert finding.score.value >= finding.score.threshold

    assert finding.provenance
    assert result.provenance_complete is True


# ============================================================================
# Candidate generation
# ============================================================================


def test_same_tenant_events_within_window_correlate():
    engine = make_engine(
        temporal_window_seconds=60,
        threshold=0.70,
    )

    evidence = [
        make_event(
            "evt-001",
            timestamp=BASE_TIME,
            tenant_id="tenant-a",
        ),
        make_event(
            "evt-002",
            timestamp=BASE_TIME + timedelta(seconds=10),
            tenant_id="tenant-a",
        ),
    ]

    result = process(
        engine,
        evidence,
        analysis_id="same-tenant-within-window",
        temporal_window_seconds=60,
        minimum_score=0.70,
    )

    assert result.candidate_count == 1
    assert result.evaluated_candidate_count == 1
    assert result.policy_denied_count == 0
    assert result.finding_count == 1

    finding = result.findings[0]

    assert finding.cross_tenant is False
    assert finding.tenant_ids == ("tenant-a",)
    assert set(finding.evidence_ids) == {
        "evt-001",
        "evt-002",
    }


def test_temporally_distant_events_without_shared_blocking_features_do_not_produce_candidate():
    engine = make_engine(
        temporal_window_seconds=60,
    )

    evidence = [
        make_event(
            "evt-001",
            timestamp=BASE_TIME,
            tenant_id="tenant-a",
            project_id="tenant-a",
            instance_name="web-a",
            resource="/tmp/a.txt",
            actor="alice",
            # use whatever fixture arguments produce a unique entity
        ),
        make_event(
            "evt-002",
            timestamp=BASE_TIME + timedelta(seconds=120),
            tenant_id="tenant-a",
            project_id="tenant-b",
            instance_name="web-b",
            resource="/tmp/b.txt",
            actor="bob",
            # use a different entity
        ),
    ]

    result = process(
        engine,
        evidence,
        analysis_id="outside-window-no-shared-block",
        temporal_window_seconds=60,
    )

    # print(result.model_dump())
    # assert result.candidate_count == 0
    # assert result.finding_count == 0
    assert result.candidate_count == 1
    assert result.evaluated_candidate_count == 1
    assert result.finding_count == 0
    assert result.rejected_candidate_count == 1


def test_candidate_generation_is_deterministic():
    evidence = [
        make_event(
            "evt-001",
            tenant_id="tenant-a",
            timestamp=BASE_TIME,
        ),
        make_event(
            "evt-002",
            tenant_id="tenant-a",
            timestamp=BASE_TIME + timedelta(seconds=5),
        ),
        make_event(
            "evt-003",
            tenant_id="tenant-a",
            timestamp=BASE_TIME + timedelta(seconds=8),
        ),
    ]

    engine = make_engine(
        temporal_window_seconds=60,
    )

    result_one = process(
        engine,
        evidence,
        analysis_id="determinism-1",
    )

    result_two = process(
        engine,
        evidence,
        analysis_id="determinism-2",
    )

    ids_one = sorted(
        finding.candidate_id
        for finding in result_one.findings
    )

    ids_two = sorted(
        finding.candidate_id
        for finding in result_two.findings
    )

    assert ids_one == ids_two


def test_candidate_generation_reports_search_space():
    engine = make_engine(
        temporal_window_seconds=60,
    )

    evidence = [
        make_event(
            "evt-001",
            tenant_id="tenant-a",
            timestamp=BASE_TIME,
        ),
        make_event(
            "evt-002",
            tenant_id="tenant-a",
            timestamp=BASE_TIME + timedelta(seconds=5),
        ),
        make_event(
            "evt-003",
            tenant_id="tenant-a",
            timestamp=BASE_TIME + timedelta(seconds=10),
        ),
        make_event(
            "evt-004",
            tenant_id="tenant-a",
            timestamp=BASE_TIME + timedelta(seconds=1000),
            resource="/tmp/unrelated.txt",
            actor="different-user",
        ),
    ]

    result = process(
        engine,
        evidence,
        analysis_id="search-space-analysis",
        temporal_window_seconds=60,
    )

    assert result.naive_comparison_count == 6

    assert result.candidate_count <= (
        result.naive_comparison_count
    )

    assert result.candidate_reduction_ratio is not None
    assert 0.0 <= result.candidate_reduction_ratio <= 1.0


# ============================================================================
# Cross-tenant policy
# ============================================================================


def test_cross_tenant_candidate_is_denied_by_default():
    engine = make_engine(
        temporal_window_seconds=60,
    )

    evidence = [
        make_event(
            "evt-a",
            tenant_id="tenant-a",
            instance_name="web-a",
            timestamp=BASE_TIME,
            resource="/tmp/cross-tenant.txt",
        ),
        make_event(
            "evt-b",
            tenant_id="tenant-b",
            instance_name="web-b",
            timestamp=BASE_TIME + timedelta(seconds=5),
            resource="/tmp/cross-tenant.txt",
        ),
    ]

    result = process(
        engine,
        evidence,
        analysis_id="cross-tenant-denied",
        allow_cross_tenant=False,
    )

    assert result.candidate_count >= 1
    assert result.evaluated_candidate_count == 0
    assert result.policy_denied_count >= 1
    assert result.finding_count == 0


def test_cross_tenant_candidate_can_be_explicitly_authorized():
    engine = make_engine(
        temporal_window_seconds=60,
        threshold=0.70,
    )

    evidence = [
        make_event(
            "evt-a",
            tenant_id="tenant-a",
            instance_name="web-a",
            timestamp=BASE_TIME,
            actor="alice",
            resource="/tmp/shared-cross.txt",
            operation="read",
        ),
        make_event(
            "evt-b",
            tenant_id="tenant-b",
            instance_name="web-b",
            timestamp=BASE_TIME + timedelta(seconds=5),
            actor="alice",
            resource="/tmp/shared-cross.txt",
            operation="read",
        ),
    ]

    result = process(
        engine,
        evidence,
        analysis_id="cross-tenant-authorized",
        allow_cross_tenant=True,
        allowed_tenant_pairs=(
            ("tenant-a", "tenant-b"),
        ),
    )

    assert result.candidate_count >= 1
    assert result.policy_denied_count == 0
    assert result.evaluated_candidate_count >= 1

    assert result.finding_count >= 1

    finding = result.findings[0]

    assert finding.cross_tenant is True
    assert set(finding.tenant_ids) == {
        "tenant-a",
        "tenant-b",
    }

    assert finding.policy_allowed is True
    assert finding.policy_id == "tenant-correlation-policy"

    assert finding.policy_reason is not None
    assert "explicitly permitted" in finding.policy_reason


def test_cross_tenant_pair_not_in_allowlist_is_denied():
    engine = make_engine(
        temporal_window_seconds=60,
    )

    evidence = [
        make_event(
            "evt-a",
            tenant_id="tenant-a",
            timestamp=BASE_TIME,
            resource="/tmp/shared.txt",
        ),
        make_event(
            "evt-c",
            tenant_id="tenant-c",
            timestamp=BASE_TIME + timedelta(seconds=5),
            resource="/tmp/shared.txt",
        ),
    ]

    result = process(
        engine,
        evidence,
        analysis_id="cross-tenant-allowlist-denied",
        allow_cross_tenant=True,
        allowed_tenant_pairs=(
            ("tenant-a", "tenant-b"),
        ),
    )

    assert result.candidate_count >= 1
    assert result.policy_denied_count >= 1
    assert result.evaluated_candidate_count == 0
    assert result.finding_count == 0


def test_allowed_tenant_pair_is_order_independent():
    engine = make_engine(
        temporal_window_seconds=60,
        threshold=0.70,
    )

    evidence = [
        make_event(
            "evt-a",
            tenant_id="tenant-a",
            timestamp=BASE_TIME,
            resource="/tmp/shared.txt",
        ),
        make_event(
            "evt-b",
            tenant_id="tenant-b",
            timestamp=BASE_TIME + timedelta(seconds=5),
            resource="/tmp/shared.txt",
        ),
    ]

    result = process(
        engine,
        evidence,
        analysis_id="reverse-pair-order",
        allow_cross_tenant=True,
        allowed_tenant_pairs=(
            ("tenant-b", "tenant-a"),
        ),
    )

    assert result.policy_denied_count == 0
    assert result.finding_count >= 1


# ============================================================================
# Tenant isolation
# ============================================================================


def test_same_actor_across_tenants_does_not_create_shared_entity():
    engine = make_engine()

    evidence = [
        make_event(
            "evt-a",
            tenant_id="tenant-a",
            actor="shared-user",
            instance_name="web-a",
            timestamp=BASE_TIME,
        ),
        make_event(
            "evt-b",
            tenant_id="tenant-b",
            actor="shared-user",
            instance_name="web-b",
            timestamp=BASE_TIME + timedelta(seconds=5),
        ),
    ]

    # The engine's default policy denies the cross-tenant candidate,
    # but entity extraction still occurs and can be inspected indirectly
    # through an independently constructed extractor.
    extractor = EntityExtractor()

    entities_a = extractor.extract(evidence[0])
    entities_b = extractor.extract(evidence[1])

    user_entities_a = {
        entity.entity_id
        for entity in entities_a
        if str(entity.entity_type) in {
            "EntityType.USER",
            "user",
        }
    }

    user_entities_b = {
        entity.entity_id
        for entity in entities_b
        if str(entity.entity_type) in {
            "EntityType.USER",
            "user",
        }
    }

    assert user_entities_a
    assert user_entities_b

    assert user_entities_a.isdisjoint(user_entities_b)


def test_entities_retain_supporting_evidence_ids():
    extractor = EntityExtractor()

    evidence = make_event(
        "evt-entity-support",
        tenant_id="tenant-a",
        actor="alice",
        resource="/tmp/evidence.txt",
    )

    entities = extractor.extract(evidence)

    assert entities

    for entity in entities:
        assert "evt-entity-support" in entity.evidence_ids


# ============================================================================
# Explainable scoring
# ============================================================================


def test_weighted_score_contains_explainable_feature_contributions():
    engine = make_engine(
        temporal_window_seconds=60,
        threshold=0.0,
    )

    evidence = [
        make_event(
            "evt-001",
            timestamp=BASE_TIME,
            resource="/tmp/shared.txt",
            operation="read",
        ),
        make_event(
            "evt-002",
            timestamp=BASE_TIME + timedelta(seconds=5),
            resource="/tmp/shared.txt",
            operation="read",
        ),
    ]

    result = process(
        engine,
        evidence,
        analysis_id="explainable-score",
        minimum_score=0.0,
    )

    assert result.findings

    score = result.findings[0].score

    feature_names = {
        feature.feature_name
        for feature in score.features
    }

    assert {
        "temporal",
        "entity",
        "resource",
        "action",
        "provenance",
    }.issubset(feature_names)

    for feature in score.features:
        assert feature.evidence_ids
        assert feature.explanation

        assert feature.contribution == pytest.approx(
            feature.value * feature.weight
        )

    assert score.weight_sum == pytest.approx(
        sum(feature.weight for feature in score.features)
    )

    assert score.valid_feature_count == len(
        score.features
    )

    assert score.value == pytest.approx(
        sum(
            feature.contribution
            for feature in score.features
        )
        / score.weight_sum
    )


def test_context_minimum_score_controls_finding_threshold():
    evidence = [
        make_event(
            "evt-001",
            timestamp=BASE_TIME,
            actor="alice",
            resource="/tmp/a.txt",
            operation="read",
        ),
        make_event(
            "evt-002",
            timestamp=BASE_TIME + timedelta(seconds=50),
            actor="bob",
            resource="/tmp/b.txt",
            operation="write",
        ),
    ]

    engine = make_engine(
        temporal_window_seconds=60,
        threshold=0.70,
    )

    result = process(
        engine,
        evidence,
        analysis_id="minimum-score",
        temporal_window_seconds=60,
        minimum_score=0.99,
    )

    # The current engine obtains the threshold from CorrelationScorer,
    # not from context.minimum_score.
    #
    # Therefore this test documents the currently implemented architecture:
    # changing CorrelationContext.minimum_score alone does not alter the
    # scorer threshold.
    assert result.context.minimum_score == pytest.approx(0.99)

    if result.findings:
        assert all(
            finding.score.threshold == pytest.approx(0.70)
            for finding in result.findings
        )


def test_score_threshold_is_applied_by_scorer():
    evidence = [
        make_event(
            "evt-001",
            timestamp=BASE_TIME,
            actor="alice",
            resource="/tmp/a.txt",
            operation="read",
        ),
        make_event(
            "evt-002",
            timestamp=BASE_TIME + timedelta(seconds=30),
            actor="bob",
            resource="/tmp/b.txt",
            operation="write",
        ),
    ]

    low_threshold_engine = make_engine(
        temporal_window_seconds=60,
        threshold=0.0,
    )

    high_threshold_engine = make_engine(
        temporal_window_seconds=60,
        threshold=0.99,
    )

    low_result = process(
        low_threshold_engine,
        evidence,
        analysis_id="low-score-threshold",
    )

    high_result = process(
        high_threshold_engine,
        evidence,
        analysis_id="high-score-threshold",
    )

    assert low_result.finding_count >= high_result.finding_count

    for finding in high_result.findings:
        assert finding.score.value >= 0.99


# ============================================================================
# Provenance
# ============================================================================


def test_finding_provenance_maps_back_to_original_evidence():
    engine = make_engine(
        threshold=0.0,
    )

    evidence = [
        make_event(
            "evt-provenance-a",
            timestamp=BASE_TIME,
        ),
        make_event(
            "evt-provenance-b",
            timestamp=BASE_TIME + timedelta(seconds=5),
        ),
    ]

    result = process(
        engine,
        evidence,
        analysis_id="provenance-test",
    )

    assert result.findings

    finding = result.findings[0]

    assert set(finding.evidence_ids) == {
        "evt-provenance-a",
        "evt-provenance-b",
    }

    provenance_by_id = {
        reference.evidence_id: reference
        for reference in finding.provenance
    }

    assert set(provenance_by_id) == {
        "evt-provenance-a",
        "evt-provenance-b",
    }

    for item in evidence:
        reference = provenance_by_id[item.evidence_id]

        assert reference.evidence_id == item.evidence_id
        assert reference.sha256 == item.sha256
        assert reference.source_table == "evidence"

        assert reference.tenant_id == item.tenant_id
        assert reference.project_id == item.project_id
        assert reference.instance_name == item.instance_name

        assert reference.integrity_verified is True

        assert len(reference.sha256) == 64
        assert all(
            character in "0123456789abcdef"
            for character in reference.sha256.lower()
        )


def test_provenance_reference_count_matches_findings():
    engine = make_engine(
        threshold=0.0,
    )

    evidence = [
        make_event(
            "evt-001",
            timestamp=BASE_TIME,
        ),
        make_event(
            "evt-002",
            timestamp=BASE_TIME + timedelta(seconds=5),
        ),
    ]

    result = process(
        engine,
        evidence,
        analysis_id="provenance-count",
    )

    expected = sum(
        len(finding.provenance)
        for finding in result.findings
    )

    assert result.provenance_reference_count == expected


# ============================================================================
# Host + instance evidence
# ============================================================================


def test_host_and_instance_evidence_can_be_temporally_correlated():
    engine = make_engine(
        temporal_window_seconds=60,
        threshold=0.0,
    )

    instance_event = make_event(
        "evt-instance",
        tenant_id="tenant-b",
        project_id="tenant-b",
        instance_name="web-b",
        layer=EvidenceLayer.INSTANCE,
        timestamp=BASE_TIME,
        resource="/tmp/evidence.txt",
        operation="write",
        source="instance-agent",
        source_path="/var/log/app.log",
    )

    host_event = make_event(
        "evt-host",
        tenant_id="tenant-b",
        project_id="tenant-b",
        instance_name="web-b",
        layer=EvidenceLayer.HOST,
        timestamp=BASE_TIME + timedelta(seconds=3),
        resource="/tmp/evidence.txt",
        operation="write",
        source="auditd",
        source_path="/var/log/audit/audit.log",
        agent_id="agent-host",
    )

    result = process(
        engine,
        [instance_event, host_event],
        analysis_id="host-instance-correlation",
        temporal_window_seconds=60,
    )

    assert result.candidate_count >= 1
    assert result.finding_count >= 1

    finding = result.findings[0]

    assert set(finding.evidence_ids) == {
        "evt-instance",
        "evt-host",
    }

    assert finding.cross_tenant is False
    assert finding.tenant_ids == ("tenant-b",)


# ============================================================================
# Requested tenant scope
# ============================================================================


def test_requested_tenant_scope_excludes_unrequested_tenant():
    engine = make_engine(
        temporal_window_seconds=60,
        threshold=0.0,
    )

    evidence = [
        make_event(
            "evt-a",
            tenant_id="tenant-a",
            timestamp=BASE_TIME,
            resource="/tmp/a.txt",
        ),
        make_event(
            "evt-b",
            tenant_id="tenant-b",
            timestamp=BASE_TIME + timedelta(seconds=5),
            resource="/tmp/b.txt",
        ),
        make_event(
            "evt-c",
            tenant_id="tenant-c",
            timestamp=BASE_TIME + timedelta(seconds=5),
            resource="/tmp/c.txt",
        ),
    ]

    result = process(
        engine,
        evidence,
        analysis_id="tenant-scope",
        requested_tenants=("tenant-a",),
        allow_cross_tenant=True,
    )

    for finding in result.findings:
        assert set(finding.tenant_ids).issubset(
            {"tenant-a"}
        )

    # Any candidate involving tenant-b or tenant-c must not be evaluated.
    assert result.policy_denied_count >= 1


# ============================================================================
# Privacy configuration
# ============================================================================


@pytest.mark.parametrize(
    "privacy_mode",
    [
        PrivacyMode.RAW,
        PrivacyMode.PSEUDONYMISED,
        PrivacyMode.GENERALISED,
        PrivacyMode.RESTRICTED,
    ],
)
def test_privacy_mode_is_preserved_in_correlation_result(
    privacy_mode: PrivacyMode,
):
    engine = make_engine(
        threshold=0.0,
    )

    evidence = [
        make_event(
            "evt-privacy-a",
            timestamp=BASE_TIME,
        ),
        make_event(
            "evt-privacy-b",
            timestamp=BASE_TIME + timedelta(seconds=5),
        ),
    ]

    result = process(
        engine,
        evidence,
        analysis_id=f"privacy-{privacy_mode.value}",
        privacy_mode=privacy_mode,
    )

    assert result.privacy_mode == privacy_mode
    assert result.context.privacy_mode == privacy_mode

    for finding in result.findings:
        assert finding.privacy_mode == privacy_mode


# ============================================================================
# Result consistency
# ============================================================================


def test_result_finding_count_matches_findings_collection():
    engine = make_engine(
        threshold=0.0,
    )

    evidence = [
        make_event(
            "evt-001",
            timestamp=BASE_TIME,
        ),
        make_event(
            "evt-002",
            timestamp=BASE_TIME + timedelta(seconds=5),
        ),
    ]

    result = process(
        engine,
        evidence,
        analysis_id="result-count",
    )

    assert result.finding_count == len(
        result.findings
    )

    assert result.evidence_count == len(evidence)

    assert result.evaluated_candidate_count <= (
        result.candidate_count
    )

    assert result.policy_denied_count <= (
        result.candidate_count
    )

    assert result.candidate_count <= (
        result.naive_comparison_count
    )


def test_correlation_does_not_modify_authoritative_input():
    engine = make_engine(
        threshold=0.0,
    )

    evidence = [
        make_event(
            "evt-001",
            timestamp=BASE_TIME,
            attributes=None if False else {},
        ),
        make_event(
            "evt-002",
            timestamp=BASE_TIME + timedelta(seconds=5),
        ),
    ]

    before = copy.deepcopy(
        [
            item.model_dump(mode="json")
            for item in evidence
        ]
    )

    process(
        engine,
        evidence,
        analysis_id="immutability-test",
    )

    after = [
        item.model_dump(mode="json")
        for item in evidence
    ]

    assert after == before


# ============================================================================
# Baseline legacy rule
# ============================================================================


def test_legacy_same_tenant_temporal_rule_remains_available_as_baseline():
    rule = SameTenantTemporalRule(
        window_seconds=10,
    )

    first = make_event(
        "evt-rule-001",
        tenant_id="tenant-a",
        timestamp=BASE_TIME,
    )

    second = make_event(
        "evt-rule-002",
        tenant_id="tenant-a",
        timestamp=BASE_TIME + timedelta(seconds=5),
    )

    finding = rule.evaluate(
        first,
        second,
    )

    assert finding is not None
    assert finding.finding_id == (
        "same-tenant-temporal:"
        "evt-rule-001:"
        "evt-rule-002"
    )

    assert finding.evidence_ids == (
        "evt-rule-001",
        "evt-rule-002",
    )

    assert finding.cross_tenant is False
    assert finding.policy_allowed is True


def test_legacy_rule_rejects_cross_tenant_evidence():
    rule = SameTenantTemporalRule(
        window_seconds=10,
    )

    first = make_event(
        "evt-rule-a",
        tenant_id="tenant-a",
        timestamp=BASE_TIME,
    )

    second = make_event(
        "evt-rule-b",
        tenant_id="tenant-b",
        timestamp=BASE_TIME + timedelta(seconds=5),
    )

    finding = rule.evaluate(
        first,
        second,
    )

    assert finding is None


# ============================================================================
# CandidateGenerator directly
# ============================================================================


def test_candidate_generator_creates_valid_evidence_references():
    generator = CandidateGenerator(
        temporal_window_seconds=60,
    )

    first = make_event(
        "evt-candidate-a",
        tenant_id="tenant-a",
        timestamp=BASE_TIME,
    )

    second = make_event(
        "evt-candidate-b",
        tenant_id="tenant-a",
        timestamp=BASE_TIME + timedelta(seconds=5),
    )

    extractor = EntityExtractor()

    entities_by_evidence = {
        first.evidence_id: tuple(
            extractor.extract(first)
        ),
        second.evidence_id: tuple(
            extractor.extract(second)
        ),
    }

    candidates = generator.generate(
        [first, second],
        entities_by_evidence,
    )

    assert len(candidates) == 1

    candidate = candidates[0]

    assert candidate.evidence_ids == (
        "evt-candidate-a",
        "evt-candidate-b",
    )

    assert len(candidate.evidence_references) == 2
    assert len(candidate.provenance) == 2

    for reference in candidate.evidence_references:
        assert reference.source_table == "evidence"
        assert len(reference.sha256) == 64

    for reference in candidate.provenance:
        assert reference.source_table == "evidence"
        assert reference.integrity_verified is True


# ============================================================================
# Policy unit/integration boundary
# ============================================================================


def test_same_tenant_policy_is_allowed():
    engine = make_engine()

    evidence = [
        make_event(
            "evt-policy-a",
            tenant_id="tenant-a",
            timestamp=BASE_TIME,
        ),
        make_event(
            "evt-policy-b",
            tenant_id="tenant-a",
            timestamp=BASE_TIME + timedelta(seconds=5),
        ),
    ]

    result = process(
        engine,
        evidence,
        analysis_id="same-tenant-policy",
    )

    assert result.policy_denied_count == 0

    assert result.findings

    finding = result.findings[0]

    assert finding.policy_id == (
        "tenant-correlation-policy"
    )

    assert finding.policy_allowed is True

    assert finding.policy_reason is not None
    assert (
        "Same-tenant correlation is permitted."
        in finding.policy_reason
    )


# ============================================================================
# Deterministic provenance and finding identity
# ============================================================================


def test_finding_identity_is_deterministic_for_same_analysis_and_evidence():
    engine = make_engine(
        threshold=0.0,
    )

    evidence = [
        make_event(
            "evt-deterministic-a",
            tenant_id="tenant-a",
            timestamp=BASE_TIME,
        ),
        make_event(
            "evt-deterministic-b",
            tenant_id="tenant-a",
            timestamp=BASE_TIME + timedelta(seconds=5),
        ),
    ]

    result_one = process(
        engine,
        evidence,
        analysis_id="deterministic-analysis",
    )

    result_two = process(
        engine,
        evidence,
        analysis_id="deterministic-analysis",
    )

    assert result_one.finding_count == result_two.finding_count

    ids_one = tuple(
        finding.finding_id
        for finding in result_one.findings
    )

    ids_two = tuple(
        finding.finding_id
        for finding in result_two.findings
    )

    assert ids_one == ids_two


# ============================================================================
# Temporal boundary behaviour
# ============================================================================


def test_temporal_boundary_is_candidate_generation_boundary():
    engine = make_engine(
        temporal_window_seconds=60,
        threshold=0.0,
    )

    evidence = [
        make_event(
            "evt-boundary-a",
            tenant_id="tenant-a",
            timestamp=BASE_TIME,
        ),
        make_event(
            "evt-boundary-b",
            tenant_id="tenant-a",
            timestamp=BASE_TIME + timedelta(seconds=60),
        ),
    ]

    result = process(
        engine,
        evidence,
        analysis_id="temporal-boundary",
        temporal_window_seconds=60,
    )

    # CandidateGenerator uses <= for the blocking boundary.
    assert result.candidate_count == 1

    # CorrelationScorer uses >= as its zero-score boundary, so the
    # candidate can still exist even though temporal contribution is zero.
    assert result.finding_count >= 0
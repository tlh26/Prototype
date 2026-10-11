# correlation/causal.py

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Mapping

from correlation.models import (
    CanonicalEvidence,
    CausalLink,
    CausalReasoningResult,
    CausalRelation,
    CorrelationCandidate,
    CorrelationContext,
)


# ============================================================================
# Causal action definitions
# ============================================================================


@dataclass(frozen=True)
class CausalActionDefinition:
    """
    Semantic definition of an event type used by the causal reasoner.

    The event names intentionally correspond to event types already produced
    by the prototype's evidence model rather than introducing a second,
    unrelated event taxonomy.
    """

    action: str
    description: str

    requires: tuple[str, ...] = ()
    provides: tuple[str, ...] = ()
    enables: tuple[str, ...] = ()

    resource_bound: bool = False


# ---------------------------------------------------------------------------
# Initial causal vocabulary
# ---------------------------------------------------------------------------
#
# These definitions are deliberately conservative.
#
# REQUIRES:
#     The later event explicitly depends on an earlier event/state.
#
# PROVIDES:
#     The earlier event creates or establishes a resource/state that the
#     later event operates on.
#
# ENABLES:
#     The earlier event creates a condition in which the later event can
#     occur, without asserting that it directly created the later resource.
#
# ---------------------------------------------------------------------------

ACTION_DEFINITIONS: dict[str, CausalActionDefinition] = {
    "LOGIN_SUCCESS": CausalActionDefinition(
        action="LOGIN_SUCCESS",
        description=(
            "A successful authentication event establishing an "
            "authenticated execution context."
        ),
        enables=("SESSION_CREATED",),
    ),
    "LOGIN_FAILURE": CausalActionDefinition(
        action="LOGIN_FAILURE",
        description=(
            "An unsuccessful authentication attempt."
        ),
    ),
    "LOGOUT": CausalActionDefinition(
        action="LOGOUT",
        description=(
            "Explicit termination of an authenticated user session."
        ),
        requires=("SESSION_CREATED",),
    ),
    "SESSION_CREATED": CausalActionDefinition(
        action="SESSION_CREATED",
        description=(
            "Creation of an authenticated or application session."
        ),
        enables=("RESOURCE_READ",),
        # requires=("LOGIN_SUCCESS",),
    ),
    "SESSION_TERMINATED": CausalActionDefinition(
        action="SESSION_TERMINATED",
        description=(
            "Termination of a previously created session."
        ),
        requires=("SESSION_CREATED",),
    ),
    "RESOURCE_CREATE": CausalActionDefinition(
        action="RESOURCE_CREATE",
        description=(
            "Creation of a logical or application resource."
        ),
        provides=(
            "RESOURCE_READ",
            "RESOURCE_UPDATE",
        ),
        resource_bound=True,
    ),
    "RESOURCE_READ": CausalActionDefinition(
        action="RESOURCE_READ",
        description=(
            "Read/access operation against an existing resource."
        ),
        resource_bound=True,
    ),
    "RESOURCE_UPDATE": CausalActionDefinition(
        action="RESOURCE_UPDATE",
        description=(
            "Modification of an existing resource."
        ),
        resource_bound=True,
    ),
    "FILE_CREATE": CausalActionDefinition(
        action="FILE_CREATE",
        description=(
            "Creation of a file-system resource."
        ),
        provides=("FILE_READ",),
        resource_bound=True,
    ),
    "FILE_READ": CausalActionDefinition(
        action="FILE_READ",
        description=(
            "Read operation against a file-system resource."
        ),
        resource_bound=True,
    ),
}


# ============================================================================
# Causal rule representation
# ============================================================================


@dataclass(frozen=True)
class _CausalRule:
    """
    Internal executable causal rule.

    source_action and target_action describe the temporal action pair.

    relation determines how the pair is represented:

        source PROVIDES target
        source ENABLES target

    or:

        source REQUIRES target

    For REQUIRES, source_action is normally the later event and
    target_action is the earlier prerequisite event.
    """

    source_action: str
    target_action: str
    relation: CausalRelation
    confidence: float
    resource_required: bool = False
    explanation: str = ""


class CausalReasoner:
    """
    Conservative rule-based causal reasoning layer.

    The reasoner does not change the multi-factor correlation score.

    Its responsibility is to determine whether two already-generated and
    policy-authorised evidence items exhibit a plausible causal relationship.

    Processing model:

        candidate
            ↓
        action extraction
            ↓
        temporal ordering
            ↓
        resource compatibility
            ↓
        causal rule matching
            ↓
        explainable causal relationship
    """

    VERSION = "1.0"

    # Explicit rules make the reasoning reproducible and inspectable.
    RULES: tuple[_CausalRule, ...] = (
        # --------------------------------------------------------------
        # Authentication / session lifecycle
        # --------------------------------------------------------------
        _CausalRule(
            source_action="LOGIN_SUCCESS",
            target_action="SESSION_CREATED",
            relation=CausalRelation.ENABLES,
            confidence=0.95,
            explanation=(
                "A successful login establishes the authenticated context "
                "under which a session can be created."
            ),
        ),
        # _CausalRule(
        #     source_action="SESSION_CREATED",
        #     target_action="LOGIN_SUCCESS",
        #     relation=CausalRelation.REQUIRES,
        #     confidence=0.90,
        #     explanation=(
        #         "Session creation is treated as requiring a preceding "
        #         "successful authentication event."
        #     ),
        # ),
        _CausalRule(
            source_action="LOGOUT",
            target_action="SESSION_CREATED",
            relation=CausalRelation.REQUIRES,
            confidence=0.95,
            explanation=(
                "Logout requires a previously established session."
            ),
        ),
        _CausalRule(
            source_action="SESSION_TERMINATED",
            target_action="SESSION_CREATED",
            relation=CausalRelation.REQUIRES,
            confidence=0.95,
            explanation=(
                "Session termination requires a previously created session."
            ),
        ),
        _CausalRule(
            source_action="SESSION_CREATED",
            target_action="RESOURCE_READ",
            relation=CausalRelation.ENABLES,
            confidence=0.75,
            resource_required=False,
            explanation=(
                "A created session establishes a context in which resource "
                "read operations can be performed."
            ),
        ),

        # --------------------------------------------------------------
        # Logical resource lifecycle
        # --------------------------------------------------------------
        _CausalRule(
            source_action="RESOURCE_CREATE",
            target_action="RESOURCE_READ",
            relation=CausalRelation.PROVIDES,
            confidence=0.95,
            resource_required=True,
            explanation=(
                "Resource creation establishes the resource subsequently "
                "read by the later event."
            ),
        ),
        _CausalRule(
            source_action="RESOURCE_CREATE",
            target_action="RESOURCE_UPDATE",
            relation=CausalRelation.PROVIDES,
            confidence=0.95,
            resource_required=True,
            explanation=(
                "Resource creation establishes the resource subsequently "
                "updated by the later event."
            ),
        ),

        # --------------------------------------------------------------
        # File lifecycle
        # --------------------------------------------------------------
        _CausalRule(
            source_action="FILE_CREATE",
            target_action="FILE_READ",
            relation=CausalRelation.PROVIDES,
            confidence=0.95,
            resource_required=True,
            explanation=(
                "File creation establishes the file subsequently read "
                "by the later event."
            ),
        ),
    )

    def __init__(
        self,
        *,
        action_definitions: Mapping[
            str,
            CausalActionDefinition,
        ]
        | None = None,
        rules: tuple[_CausalRule, ...] | None = None,
    ) -> None:
        self.action_definitions = dict(
            action_definitions
            if action_definitions is not None
            else ACTION_DEFINITIONS
        )

        self.rules = tuple(
            rules
            if rules is not None
            else self.RULES
        )

        self._rules_by_pair = {
            (
                rule.source_action,
                rule.target_action,
            ): rule
            for rule in self.rules
        }

    # ==================================================================
    # Public API
    # ==================================================================

    def reason(
        self,
        candidate: CorrelationCandidate,
        evidence_by_id: Mapping[str, CanonicalEvidence],
        context: CorrelationContext,
    ) -> CausalReasoningResult:
        """
        Evaluate a correlation candidate for causal relationships.

        Causal reasoning is deliberately restricted to candidates that
        contain exactly two evidence items in the current implementation.

        The engine performs policy evaluation before calling this method.
        The reasoner nevertheless performs a second tenant-scope check so
        that causal links cannot accidentally bypass privacy boundaries if
        the reasoner is used independently.
        """

        evidence_ids = tuple(candidate.evidence_ids)

        if len(evidence_ids) != 2:
            return CausalReasoningResult(
                candidate_id=candidate.candidate_id,
                relationships=(),
                considered=True,
                relationship_count=0,
                explanation=(
                    "Causal reasoning currently supports pair candidates "
                    "only."
                ),
                metadata={
                    "causal_version": self.VERSION,
                    "reason": "unsupported_candidate_size",
                },
            )

        first = evidence_by_id.get(evidence_ids[0])
        second = evidence_by_id.get(evidence_ids[1])

        if first is None or second is None:
            return CausalReasoningResult(
                candidate_id=candidate.candidate_id,
                relationships=(),
                considered=False,
                relationship_count=0,
                explanation=(
                    "Causal reasoning could not resolve all evidence "
                    "references."
                ),
                metadata={
                    "causal_version": self.VERSION,
                    "reason": "missing_evidence",
                },
            )

        if not self._tenant_scope_allowed(
            first=first,
            second=second,
            context=context,
        ):
            return CausalReasoningResult(
                candidate_id=candidate.candidate_id,
                relationships=(),
                considered=False,
                relationship_count=0,
                explanation=(
                    "Causal reasoning was denied because the evidence "
                    "falls outside the authorised tenant scope."
                ),
                metadata={
                    "causal_version": self.VERSION,
                    "reason": "tenant_scope_denied",
                },
            )

        first_action = self._action_for(first)
        second_action = self._action_for(second)

        if first_action is None or second_action is None:
            return CausalReasoningResult(
                candidate_id=candidate.candidate_id,
                relationships=(),
                considered=True,
                relationship_count=0,
                explanation=(
                    "No supported causal action pair could be extracted "
                    "from the evidence."
                ),
                metadata={
                    "causal_version": self.VERSION,
                    "first_action": first_action,
                    "second_action": second_action,
                    "reason": "unsupported_action",
                },
            )

        ordering = self._order_events(
            first,
            second,
        )

        if ordering is None:
            return CausalReasoningResult(
                candidate_id=candidate.candidate_id,
                relationships=(),
                considered=True,
                relationship_count=0,
                explanation=(
                    "Causal reasoning requires a trustworthy temporal "
                    "ordering between the evidence events."
                ),
                metadata={
                    "causal_version": self.VERSION,
                    "first_action": first_action,
                    "second_action": second_action,
                    "reason": "missing_temporal_order",
                },
            )

        earlier, later, temporal_delta = ordering

        earlier_action = self._action_for(earlier)
        later_action = self._action_for(later)

        if earlier_action is None or later_action is None:
            return CausalReasoningResult(
                candidate_id=candidate.candidate_id,
                relationships=(),
                considered=True,
                relationship_count=0,
                explanation=(
                    "Temporal ordering was available, but one or more "
                    "actions were not supported by the causal vocabulary."
                ),
                metadata={
                    "causal_version": self.VERSION,
                    "reason": "unsupported_ordered_action",
                },
            )

        rule = self._find_rule(
            earlier_action=earlier_action,
            later_action=later_action,
        )

        if rule is None:
            return CausalReasoningResult(
                candidate_id=candidate.candidate_id,
                relationships=(),
                considered=True,
                relationship_count=0,
                explanation=(
                    f"No causal rule connects {earlier_action} to "
                    f"{later_action}."
                ),
                metadata={
                    "causal_version": self.VERSION,
                    "earlier_action": earlier_action,
                    "later_action": later_action,
                    "temporal_delta_seconds": temporal_delta,
                    "reason": "no_matching_rule",
                },
            )

        if (
            temporal_delta
            > context.temporal_window_seconds
        ):
            return CausalReasoningResult(
                candidate_id=candidate.candidate_id,
                relationships=(),
                considered=True,
                relationship_count=0,
                explanation=(
                    f"The causal action pair is {temporal_delta:.3f}s "
                    f"apart, exceeding the configured "
                    f"{context.temporal_window_seconds:.3f}s window."
                ),
                metadata={
                    "causal_version": self.VERSION,
                    "reason": "temporal_window_exceeded",
                    "temporal_delta_seconds": temporal_delta,
                },
            )

        if rule.resource_required and not self._resource_compatible(
            candidate=candidate,
            earlier=earlier,
            later=later,
        ):
            return CausalReasoningResult(
                candidate_id=candidate.candidate_id,
                relationships=(),
                considered=True,
                relationship_count=0,
                explanation=(
                    f"The {rule.relation.value} relationship between "
                    f"{earlier_action} and {later_action} requires a "
                    "shared resource, but no shared resource was identified."
                ),
                metadata={
                    "causal_version": self.VERSION,
                    "reason": "resource_incompatibility",
                    "earlier_action": earlier_action,
                    "later_action": later_action,
                },
            )

        relationship = self._build_relationship(
            candidate=candidate,
            earlier=earlier,
            later=later,
            earlier_action=earlier_action,
            later_action=later_action,
            rule=rule,
            temporal_delta=temporal_delta,
        )

        return CausalReasoningResult(
            candidate_id=candidate.candidate_id,
            relationships=(relationship,),
            considered=True,
            relationship_count=1,
            explanation=(
                f"{relationship.relation.value.upper()}: "
                f"{earlier_action} → {later_action}. "
                f"{relationship.explanation}"
            ),
            metadata={
                "causal_version": self.VERSION,
                "earlier_action": earlier_action,
                "later_action": later_action,
                "temporal_delta_seconds": temporal_delta,
                "resource_required": rule.resource_required,
            },
        )

    # ==================================================================
    # Action extraction
    # ==================================================================

    def _action_for(
        self,
        evidence: CanonicalEvidence,
    ) -> str | None:
        """
        Resolve evidence to one of the supported causal actions.

        Event type is preferred because it is the prototype's normalized
        event vocabulary. Source-specific action fields are considered as
        fallbacks for evidence produced by collectors that expose a more
        detailed action classification.
        """

        candidates: list[str] = []

        if evidence.event_type:
            candidates.append(
                str(evidence.event_type)
            )

        for key in (
            "event_action",
            "action",
            "operation",
        ):
            value = evidence.attributes.get(key)

            if value is not None:
                candidates.append(
                    str(value)
                )

        for value in candidates:
            normalized = self._normalise_action(value)

            if normalized in self.action_definitions:
                return normalized

        return None

    @staticmethod
    def _normalise_action(
        value: str,
    ) -> str:
        return (
            str(value)
            .strip()
            .upper()
            .replace("-", "_")
            .replace(" ", "_")
        )

    # ==================================================================
    # Temporal reasoning
    # ==================================================================

    @staticmethod
    def _order_events(
        first: CanonicalEvidence,
        second: CanonicalEvidence,
    ) -> tuple[
        CanonicalEvidence,
        CanonicalEvidence,
        float,
    ] | None:
        """
        Establish a trustworthy temporal ordering.

        Current Phase 3 intentionally requires event timestamps. Collection
        time is not substituted because doing so could manufacture causal
        ordering where the event occurrence time is unknown.
        """

        if (
            first.event_timestamp is None
            or second.event_timestamp is None
        ):
            return None

        if first.event_timestamp <= second.event_timestamp:
            earlier = first
            later = second
        else:
            earlier = second
            later = first

        delta = (
            later.event_timestamp
            - earlier.event_timestamp
        ).total_seconds()

        if delta < 0:
            return None

        return earlier, later, delta

    # ==================================================================
    # Rule matching
    # ==================================================================

    def _find_rule(
        self,
        *,
        earlier_action: str,
        later_action: str,
    ) -> _CausalRule | None:
        """
        Find the causal rule applicable to an ordered action pair.

        REQUIRES rules are encoded as:

            later_action REQUIRES earlier_action

        and therefore become a causal link whose source is the later event
        and target is the earlier prerequisite event.
        """

        # First check explicit REQUIRES semantics on the later action.
        later_definition = self.action_definitions.get(
            later_action
        )

        if (
            later_definition is not None
            and earlier_action in later_definition.requires
        ):
            return _CausalRule(
                source_action=later_action,
                target_action=earlier_action,
                relation=CausalRelation.REQUIRES,
                confidence=0.95,
                explanation=(
                    f"{later_action} explicitly requires a preceding "
                    f"{earlier_action} event."
                ),
            )

        # Then check PROVIDES/ENABLES rules from the earlier event.
        direct_rule = self._rules_by_pair.get(
            (
                earlier_action,
                later_action,
            )
        )

        return direct_rule

    # ==================================================================
    # Resource compatibility
    # ==================================================================

    @staticmethod
    def _resource_compatible(
        *,
        candidate: CorrelationCandidate,
        earlier: CanonicalEvidence,
        later: CanonicalEvidence,
    ) -> bool:
        """
        Require a shared resource for resource/file causal relationships.

        This prevents a generic FILE_CREATE in one part of the environment
        from being interpreted as causing an unrelated FILE_READ elsewhere.
        """

        if candidate.shared_resources:
            return True

        if (
            earlier.resource is not None
            and later.resource is not None
            and str(earlier.resource) == str(later.resource)
        ):
            return True

        resource_keys = (
            "resource",
            "resource_id",
            "path",
            "file",
            "file_path",
            "object",
        )

        earlier_resources = {
            str(earlier.attributes[key])
            for key in resource_keys
            if key in earlier.attributes
            and earlier.attributes[key] is not None
        }

        later_resources = {
            str(later.attributes[key])
            for key in resource_keys
            if key in later.attributes
            and later.attributes[key] is not None
        }

        return bool(
            earlier_resources
            & later_resources
        )

    # ==================================================================
    # Tenant policy defence-in-depth
    # ==================================================================

    @staticmethod
    def _tenant_scope_allowed(
        *,
        first: CanonicalEvidence,
        second: CanonicalEvidence,
        context: CorrelationContext,
    ) -> bool:
        first_tenant = first.tenant_id
        second_tenant = second.tenant_id

        if (
            first_tenant is None
            or second_tenant is None
        ):
            return True

        if first_tenant == second_tenant:
            return True

        if not context.allow_cross_tenant:
            return False

        pair = tuple(
            sorted(
                (
                    first_tenant,
                    second_tenant,
                )
            )
        )

        if context.allowed_tenant_pairs:
            allowed_pairs = {
                tuple(sorted(item))
                for item in context.allowed_tenant_pairs
            }

            if pair not in allowed_pairs:
                return False

        return True

    # ==================================================================
    # Relationship construction
    # ==================================================================

    @staticmethod
    def _build_relationship(
        *,
        candidate: CorrelationCandidate,
        earlier: CanonicalEvidence,
        later: CanonicalEvidence,
        earlier_action: str,
        later_action: str,
        rule: _CausalRule,
        temporal_delta: float,
    ) -> CausalLink:
        if rule.relation == CausalRelation.REQUIRES:
            source = later
            target = earlier
            source_action = later_action
            target_action = earlier_action
        else:
            source = earlier
            target = later
            source_action = earlier_action
            target_action = later_action

        tenant_ids = tuple(
            sorted(
                {
                    tenant_id
                    for tenant_id in (
                        source.tenant_id,
                        target.tenant_id,
                    )
                    if tenant_id is not None
                }
            )
        )

        cross_tenant = len(tenant_ids) > 1

        relationship_id = (
            f"causal:"
            f"{candidate.candidate_id}:"
            f"{rule.relation.value}:"
            f"{source.evidence_id}:"
            f"{target.evidence_id}"
        )

        explanation = (
            f"{source_action} "
            f"{rule.relation.value.upper()} "
            f"{target_action}. "
            f"{rule.explanation} "
            f"The events are {temporal_delta:.3f}s apart."
        )

        if candidate.shared_resources:
            explanation += (
                " The relationship is additionally supported by "
                "shared resource evidence."
            )

        return CausalLink(
            relationship_id=relationship_id,
            relation=rule.relation,
            source_evidence_id=source.evidence_id,
            target_evidence_id=target.evidence_id,
            source_action=source_action,
            target_action=target_action,
            evidence_ids=(
                source.evidence_id,
                target.evidence_id,
            ),
            tenant_ids=tenant_ids,
            cross_tenant=cross_tenant,
            temporal_delta_seconds=temporal_delta,
            confidence=rule.confidence,
            explanation=explanation,
            metadata={
                "causal_version": CausalReasoner.VERSION,
                "candidate_id": candidate.candidate_id,
                "resource_bound": (
                    ACTION_DEFINITIONS[source_action].resource_bound
                    or ACTION_DEFINITIONS[target_action].resource_bound
                ),
                "shared_resources": candidate.shared_resources,
            },
        )
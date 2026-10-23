# correlation/policy.py

from __future__ import annotations

from dataclasses import dataclass

from correlation.models import (
    CorrelationCandidate,
    CorrelationContext,
)


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    policy_id: str
    reason: str


class CrossTenantPolicy:
    """
    Explicit policy boundary for cross-tenant correlation.

    The policy is deliberately separate from scoring. A candidate may be
    technically strong enough to correlate while still being prohibited
    by the tenant-authorisation policy.
    """

    policy_id = "tenant-correlation-policy"
    version = "1.0"

    def evaluate(
        self,
        candidate: CorrelationCandidate,
        context: CorrelationContext,
    ) -> PolicyDecision:
        if not candidate.cross_tenant:
            return PolicyDecision(
                allowed=True,
                policy_id=self.policy_id,
                reason=(
                    "Same-tenant correlation is permitted."
                ),
            )

        if not context.allow_cross_tenant:
            return PolicyDecision(
                allowed=False,
                policy_id=self.policy_id,
                reason=(
                    "Cross-tenant correlation is disabled "
                    "by the analysis context."
                ),
            )

        if len(candidate.tenant_ids) != 2:
            return PolicyDecision(
                allowed=False,
                policy_id=self.policy_id,
                reason=(
                    "Cross-tenant correlation requires "
                    "exactly two tenants for this policy."
                ),
            )

        # if context.allowed_tenant_pairs:
        #     candidate_pair = frozenset(
        #         candidate.tenant_ids
        #     )

        #     permitted_pairs = {
        #         frozenset(pair)
        #         for pair in context.allowed_tenant_pairs
        #     }

        #     if candidate_pair not in permitted_pairs:
        #         return PolicyDecision(
        #             allowed=False,
        #             policy_id=self.policy_id,
        #             reason=(
        #                 "The tenant pair is not present in "
        #                 "the configured cross-tenant "
        #                 "allowlist."
        #             ),
        #         )


        if not context.allowed_tenant_pairs:
            return PolicyDecision(
                allowed=False,
                policy_id=self.policy_id,
                reason=(
                    "Cross-tenant correlation requires an "
                    "explicitly authorised tenant pair."
                ),
            )

        candidate_pair = frozenset(candidate.tenant_ids)

        permitted_pairs = {
            frozenset(pair)
            for pair in context.allowed_tenant_pairs
            if len(pair) == 2 and pair[0] != pair[1]
        }

        if candidate_pair not in permitted_pairs:
            return PolicyDecision(
                allowed=False,
                policy_id=self.policy_id,
                reason=(
                    "The tenant pair is not present in "
                    "the configured cross-tenant allowlist."
                ),
            )


        return PolicyDecision(
            allowed=True,
            policy_id=self.policy_id,
            reason=(
                "Cross-tenant correlation is explicitly "
                "permitted by the analysis context."
            ),
        )
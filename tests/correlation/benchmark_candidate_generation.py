from __future__ import annotations

from datetime import datetime, timedelta, timezone
from time import perf_counter

from correlation.candidateIndex import CandidateIndex
from correlation.models import CanonicalEvidence


def make_evidence(
    count: int,
) -> list[CanonicalEvidence]:
    base = datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    return [
        CanonicalEvidence(
            evidence_id=f"event-{index:08d}",
            tenant_id=f"tenant-{index % 4}",
            project_id=f"tenant-{index % 4}",
            instance_name="web",
            event_timestamp=(
                base
                + timedelta(
                    seconds=index * 5
                )
            ),
            actor=f"user-{index % 20}",
            resource=f"/tmp/resource-{index % 50}",
            attributes={
                "operation": "read",
            },
            event_type="file",
            evidence_type="audit",
            layer="event",
            source="benchmark",
            collected_at=(
                base
                + timedelta(
                    seconds=index * 5
                )
            ),
            sha256=(
                f"{index:064x}"
            ),
            provenance={
                "source_table": "benchmark",
            },
            sequence_start=None,
            sequence_end=None,
        )
        for index in range(count)
    ]


def main() -> None:
    evidence = make_evidence(10_000)

    index = CandidateIndex(
        temporal_window_seconds=60,
        include_tenant_blocking=False,
    )

    start = perf_counter()

    index.build(evidence)

    build_time = (
        perf_counter() - start
    )

    start = perf_counter()

    candidates = index.generate_pairs()

    generation_time = (
        perf_counter() - start
    )

    stats = index.stats

    print()
    print(
        "Candidate generation benchmark"
    )
    print(
        "================================"
    )
    print(
        f"Evidence records: "
        f"{stats.evidence_count:,}"
    )
    print(
        f"Theoretical pairs: "
        f"{stats.theoretical_pair_count:,}"
    )
    print(
        f"Indexed candidates: "
        f"{stats.candidate_pair_count:,}"
    )
    print(
        f"Reduction ratio: "
        f"{stats.reduction_ratio:.4%}"
    )
    print(
        f"Candidate ratio: "
        f"{stats.candidate_generation_ratio:.4%}"
    )
    print(
        f"Index build time: "
        f"{build_time:.4f}s"
    )
    print(
        f"Candidate generation time: "
        f"{generation_time:.4f}s"
    )
    print(
        f"Temporal pairs: "
        f"{stats.temporal_pair_count:,}"
    )
    print(
        f"Entity pairs: "
        f"{stats.entity_pair_count:,}"
    )
    print(
        f"Resource pairs: "
        f"{stats.resource_pair_count:,}"
    )
    print(
        f"Actor pairs: "
        f"{stats.actor_pair_count:,}"
    )
    print(
        f"Tenant pairs: "
        f"{stats.tenant_pair_count:,}"
    )
    print()


if __name__ == "__main__":
    main()
from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path

# ============================================================================
# Project imports
# ============================================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from evidenceAgent.evidenceAgent.spool import EvidenceSpool

# ============================================================================
# Configuration
# ============================================================================

SPOOL_FILE = Path(
    os.getenv(
        "REAL_HOST_SPOOL_FILE",
        "/tmp/real-host-agent-spool/spool/"
        "00000000000000000038_agent-host-smoke-test.json",
    )
)

CENTRAL_URL = os.getenv(
    "EVIDENCE_CENTRAL_URL",
    "http://192.168.64.18:9443",
)

API_KEY = os.getenv(
    "EVIDENCE_API_KEY",
    "change-me",
)

CENTRAL_DB = os.getenv(
    "CENTRAL_DATABASE",
    "storage/evidence.db",
)

REQUEST_TIMEOUT = int(os.getenv("EVIDENCE_REQUEST_TIMEOUT", "30"))

TLS_VERIFY = os.getenv("EVIDENCE_TLS_VERIFY", "true").lower() not in {
    "0",
    "false",
    "no",
}

BATCH_ENDPOINT = f"{CENTRAL_URL.rstrip('/')}/api/v1/evidence/batches"


# ============================================================================
# Output helpers
# ============================================================================


def section(number: int, title: str) -> None:
    print()
    print("=" * 78)
    print(f"{number}. {title}")
    print("=" * 78)


def passed(message: str) -> None:
    print(f"[PASS] {message}")


def info(message: str) -> None:
    print(f"[INFO] {message}")


def warning(message: str) -> None:
    print(f"[WARN] {message}")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


# ============================================================================
# Spool loading
# ============================================================================


def load_spool_file() -> tuple[EvidenceSpool, Path]:
    section(
        1,
        "Locating retained real host-agent spool",
    )

    info(f"Spool file:\n  {SPOOL_FILE}")

    require(
        SPOOL_FILE.exists(),
        (
            "Expected spool file does not exist:\n"
            f"  {SPOOL_FILE}\n\n"
            "Set REAL_HOST_SPOOL_FILE to the retained spool file."
        ),
    )

    require(
        SPOOL_FILE.is_file(),
        f"Spool path is not a regular file: {SPOOL_FILE}",
    )

    spool = EvidenceSpool(str(SPOOL_FILE.parent))

    passed(f"Spool file exists: {SPOOL_FILE}")

    return spool, SPOOL_FILE


# ============================================================================
# Batch validation
# ============================================================================


def validate_batch(batch) -> None:
    section(
        2,
        "Loading and validating EvidenceBatch",
    )

    require(
        batch.agent_id == "agent-host-smoke-test",
        ("Unexpected agent_id: " f"{batch.agent_id!r}"),
    )

    require(
        batch.evidence,
        "Spool batch contains no evidence.",
    )

    print(f"  agent_id:       {batch.agent_id}")

    print(f"  evidence count: {len(batch.evidence)}")

    passed("EvidenceSpool.load() reconstructed the EvidenceBatch.")


# ============================================================================
# Independent envelope verification
# ============================================================================


def verify_envelope(envelope) -> None:
    """
    Independently verify the transport representation.

    Central must not be the only component trusted to detect corruption.
    """

    try:
        raw_data = base64.b64decode(
            envelope.raw_data_b64,
            validate=True,
        )
    except Exception as exc:
        raise RuntimeError(
            f"Invalid Base64 for evidence " f"{envelope.evidence_id}"
        ) from exc

    require(
        len(raw_data) == envelope.size_bytes,
        (
            f"Size mismatch for evidence "
            f"{envelope.evidence_id}: "
            f"expected {envelope.size_bytes}, "
            f"got {len(raw_data)}"
        ),
    )

    actual_sha256 = hashlib.sha256(raw_data).hexdigest()

    require(
        actual_sha256 == envelope.sha256,
        (
            f"SHA-256 mismatch for evidence "
            f"{envelope.evidence_id}: "
            f"expected {envelope.sha256}, "
            f"got {actual_sha256}"
        ),
    )


def validate_all_evidence(batch) -> None:
    section(
        3,
        "Independently verifying spool evidence integrity",
    )

    for envelope in batch.evidence:
        verify_envelope(envelope)

    passed("All envelopes passed Base64, size, and SHA-256 verification.")


# ============================================================================
# Batch metadata
# ============================================================================


def inspect_batch_metadata(batch) -> None:
    section(
        4,
        "Inspecting EvidenceBatch metadata",
    )

    attributed = 0
    unattributed = 0

    for envelope in batch.evidence:
        if envelope.tenant_id is not None or envelope.instance_name is not None:
            attributed += 1
        else:
            unattributed += 1

    print(f"  agent_id:       {batch.agent_id}")

    print(f"  evidence count: {len(batch.evidence)}")

    print(f"  attributed:     {attributed}")

    print(f"  unattributed:   {unattributed}")

    passed("Batch metadata inspection completed.")


# ============================================================================
# SQLite inspection
# ============================================================================


def connect_central_database() -> sqlite3.Connection:
    require(
        CENTRAL_DB,
        (
            "CENTRAL_DB_PATH is not configured.\n"
            "Direct SQLite verification is now mandatory for this test."
        ),
    )

    db_path = Path(CENTRAL_DB)

    require(
        db_path.exists(),
        f"Central database does not exist: {db_path}",
    )

    info(f"SQLite database: {db_path}")

    connection = sqlite3.connect(db_path)

    connection.row_factory = sqlite3.Row

    return connection


def database_evidence_count(
    connection: sqlite3.Connection,
) -> int:
    row = connection.execute("""
        SELECT COUNT(*) AS count
        FROM evidence
        """).fetchone()

    return int(row["count"])


def verify_central_database(
    batch,
    *,
    expected_total_count: int | None = None,
) -> int:
    """
    Inspect Central's actual SQLite evidence table.

    Current repository schema uses:

        evidence

    rather than:

        evidence_records
    """

    section(
        5,
        "Direct SQLite persistence inspection",
    )

    connection = connect_central_database()

    try:
        total_count = database_evidence_count(connection)

        print(f"  SQLite evidence rows: {total_count}")

        if expected_total_count is not None:
            require(
                total_count == expected_total_count,
                (
                    "Unexpected Central evidence row count: "
                    f"expected {expected_total_count}, "
                    f"got {total_count}"
                ),
            )

        # ---------------------------------------------------------------
        # Duplicate primary-key detection.
        # ---------------------------------------------------------------

        duplicate_rows = connection.execute("""
            SELECT
                evidence_id,
                COUNT(*) AS count
            FROM evidence
            GROUP BY evidence_id
            HAVING COUNT(*) > 1
            """).fetchall()

        require(
            not duplicate_rows,
            ("Duplicate evidence IDs detected in Central: " f"{len(duplicate_rows)}"),
        )

        # ---------------------------------------------------------------
        # Verify every envelope.
        # ---------------------------------------------------------------

        missing = []
        mismatched = []
        integrity_failures = []

        for envelope in batch.evidence:

            row = connection.execute(
                """
                SELECT
                    evidence_id,
                    capture_id,
                    tenant_id,
                    tenant_hash,
                    project_id,
                    instance_name,
                    scope,
                    source,
                    source_path,
                    acquisition_layer,
                    acquired_from,
                    attribution_method,
                    collected_at,
                    raw_data,
                    sha256,
                    size_bytes,
                    sequence_start,
                    sequence_end,
                    record_sha256
                FROM evidence
                WHERE evidence_id = ?
                """,
                (envelope.evidence_id,),
            ).fetchone()

            if row is None:
                missing.append(envelope.evidence_id)
                continue

            raw_data = bytes(row["raw_data"])

            actual_sha256 = hashlib.sha256(raw_data).hexdigest()

            metadata_ok = (
                row["sha256"] == envelope.sha256
                and row["size_bytes"] == envelope.size_bytes
                and row["tenant_id"] == envelope.tenant_id
                and row["instance_name"] == envelope.instance_name
                and row["project_id"] == envelope.project_id
                and row["scope"] == envelope.scope
                and row["source"] == envelope.source
                and row["source_path"] == envelope.source_path
                and row["acquisition_layer"] == envelope.acquisition_layer
                and row["acquired_from"] == envelope.acquired_from
                and row["attribution_method"] == envelope.attribution_method
                and row["sequence_start"] == envelope.sequence_start
                and row["sequence_end"] == envelope.sequence_end
            )

            raw_integrity_ok = (
                actual_sha256 == envelope.sha256
                and actual_sha256 == row["sha256"]
                and len(raw_data) == row["size_bytes"]
            )

            if not metadata_ok:
                mismatched.append(envelope.evidence_id)

            if not raw_integrity_ok:
                integrity_failures.append(envelope.evidence_id)

        require(
            not missing,
            (
                "Central database is missing evidence IDs. "
                f"count={len(missing)}, "
                f"first={missing[:5]}"
            ),
        )

        require(
            not mismatched,
            (
                "Central database metadata mismatches detected. "
                f"count={len(mismatched)}, "
                f"first={mismatched[:5]}"
            ),
        )

        require(
            not integrity_failures,
            (
                "Central raw evidence integrity failures detected. "
                f"count={len(integrity_failures)}, "
                f"first={integrity_failures[:5]}"
            ),
        )

        passed("Every spool evidence record exists in SQLite.")

        passed("Every persisted raw BLOB has the expected size and SHA-256.")

        passed("Persisted provenance and sequence metadata match the spool.")

        passed("No duplicate evidence IDs exist.")

        return total_count

    finally:
        connection.close()


# ============================================================================
# Spool lifecycle inspection
# ============================================================================


def verify_spool_pending(
    spool: EvidenceSpool,
    spool_path: Path,
    *,
    expected: bool,
) -> None:
    state = "PRESENT" if expected else "ABSENT"

    print()
    print("-" * 78)
    print(f"Spool lifecycle state: expected {state}")
    print("-" * 78)

    pending = spool.pending()

    print(f"  pending entries: {len(pending)}")

    for path in pending:
        print(f"    {path}")

    if expected:
        require(
            spool_path.exists(),
            ("Expected spool entry to remain on disk, " "but it does not exist."),
        )

        require(
            spool_path in pending,
            ("Expected spool entry to appear in " "EvidenceSpool.pending()."),
        )

        passed("Spool entry is retained and pending.")

    else:
        require(
            not spool_path.exists(),
            ("Spool entry should have been removed " "after successful delivery."),
        )

        require(
            spool_path not in pending,
            ("Removed spool entry still appears in " "EvidenceSpool.pending()."),
        )

        passed("Spool entry was removed and is no longer pending.")


def verify_remove_directly(
    spool: EvidenceSpool,
    spool_path: Path,
) -> None:
    """
    Explicitly verify EvidenceSpool.remove().

    This section is deliberately performed only after the Central
    persistence test has established that the evidence is already
    safely stored.

    It verifies the spool primitive independently from the delivery
    component.
    """

    section(
        6,
        "Verifying EvidenceSpool.remove()",
    )

    require(
        spool_path.exists(),
        ("Cannot test EvidenceSpool.remove(): " "spool file no longer exists."),
    )

    info(f"Removing spool entry:\n  {spool_path}")

    spool.remove(spool_path)

    require(
        not spool_path.exists(),
        ("EvidenceSpool.remove() returned, " "but the spool file still exists."),
    )

    require(
        spool_path not in spool.pending(),
        ("EvidenceSpool.remove() removed the file " "but it remains in pending()."),
    )

    passed("EvidenceSpool.remove() successfully removed " "the delivered spool entry.")


# ============================================================================
# Central target
# ============================================================================


def inspect_central_target() -> None:
    section(
        7,
        "Inspecting Central delivery configuration",
    )

    print(f"  Central URL: {CENTRAL_URL}")

    print(f"  Endpoint:    {BATCH_ENDPOINT}")

    print(f"  TLS verify:  {TLS_VERIFY}")

    require(
        API_KEY,
        "EVIDENCE_API_KEY is empty.",
    )

    passed("Central delivery configuration is present.")


# ============================================================================
# ACTUAL DELIVERY COMPONENT
# ============================================================================


def build_delivery_component(
    *,
    central_url: str,
    api_key: str,
    spool: EvidenceSpool,
):
    """
    Construct the ACTUAL production delivery/retry component.

    IMPORTANT:
    Replace the import and constructor below with the exact component
    implemented in the current evidence-agent codebase.

    Do NOT replace this with post_batch().

    The component under test must own the lifecycle:

        spool.load()
            ->
        Central delivery
            ->
        successful acknowledgement
            ->
        spool.remove()

    and:

        Central failure
            ->
        retain spool
    """

    # ------------------------------------------------------------------
    # TODO: Wire this to the project's actual implementation.
    #
    # Example shape only:
    #
    # from evidenceAgent.evidenceAgent.delivery import (
    #     EvidenceDeliveryService,
    # )
    #
    # return EvidenceDeliveryService(
    #     central_url=central_url,
    #     api_key=api_key,
    #     spool=spool,
    # )
    #
    # ------------------------------------------------------------------

    raise RuntimeError(
        "Actual Central delivery/retry component has not been wired "
        "into this test. Replace build_delivery_component() with the "
        "real project implementation rather than testing through "
        "post_batch()."
    )


# ============================================================================
# Delivery lifecycle
# ============================================================================


def test_delivery_lifecycle(
    spool: EvidenceSpool,
    spool_path: Path,
    batch,
) -> None:
    section(
        8,
        "Testing Central delivery/retry lifecycle",
    )

    delivery = build_delivery_component(
        central_url=CENTRAL_URL,
        api_key=API_KEY,
        spool=spool,
    )

    # ------------------------------------------------------------------
    # IMPORTANT:
    #
    # The test must use the actual retry/delivery method here.
    #
    # The exact call depends on the current implementation.
    # ------------------------------------------------------------------

    info("Attempting delivery through the actual " "Central delivery component.")

    result = delivery.deliver(spool_path)

    require(
        result.success,
        ("Central delivery component reported failure: " f"{result}"),
    )

    # Successful Central acknowledgement MUST precede spool removal.
    verify_spool_pending(
        spool,
        spool_path,
        expected=False,
    )

    passed("Successful Central delivery removed the spool entry.")


# ============================================================================
# Main
# ============================================================================


def main() -> None:
    print()
    print("=" * 78)
    print("REAL SPOOL -> CENTRAL DELIVERY LIFECYCLE TEST")
    print("=" * 78)

    print()
    print("This test validates:")
    print(
        "  spool"
        " ->"
        " integrity"
        " ->"
        " Central"
        " ->"
        " SQLite"
        " ->"
        " delivery acknowledgement"
        " ->"
        " spool removal"
    )

    # ------------------------------------------------------------------
    # 1-4. Locate, load, validate.
    # ------------------------------------------------------------------

    spool, spool_path = load_spool_file()

    batch = spool.load(spool_path)

    validate_batch(batch)

    validate_all_evidence(batch)

    inspect_batch_metadata(batch)

    # ------------------------------------------------------------------
    # 5. Direct SQLite verification.
    # ------------------------------------------------------------------

    before_count = verify_central_database(batch)

    info(f"SQLite row count before lifecycle test: " f"{before_count}")

    # ------------------------------------------------------------------
    # 6. Confirm spool currently exists.
    # ------------------------------------------------------------------

    section(
        6,
        "Verifying spool is pending before delivery",
    )

    verify_spool_pending(
        spool,
        spool_path,
        expected=True,
    )

    # ------------------------------------------------------------------
    # 7. Central configuration.
    # ------------------------------------------------------------------

    inspect_central_target()

    # ------------------------------------------------------------------
    # 8. Actual delivery/retry component.
    # ------------------------------------------------------------------

    test_delivery_lifecycle(
        spool,
        spool_path,
        batch,
    )

    # ------------------------------------------------------------------
    # 9. Verify Central database after delivery.
    # ------------------------------------------------------------------

    section(
        9,
        "Verifying SQLite after successful delivery",
    )

    after_count = verify_central_database(batch)

    require(
        after_count == before_count,
        (
            "Successful delivery changed the total evidence row "
            "count unexpectedly: "
            f"before={before_count}, "
            f"after={after_count}"
        ),
    )

    passed("Successful delivery did not create duplicate evidence.")

    # ------------------------------------------------------------------
    # 10. Final result.
    # ------------------------------------------------------------------

    section(
        10,
        "Final result",
    )

    print("REAL SPOOL -> CENTRAL DELIVERY LIFECYCLE TEST PASSED")

    print()
    print("Validated:")
    print("  [PASS] Existing real host-agent spool located")
    print("  [PASS] EvidenceSpool.load()")
    print("  [PASS] Base64 verification")
    print("  [PASS] Size verification")
    print("  [PASS] SHA-256 verification")
    print("  [PASS] Batch metadata inspection")
    print("  [PASS] Direct SQLite persistence")
    print("  [PASS] SQLite raw-data integrity")
    print("  [PASS] SQLite provenance verification")
    print("  [PASS] Duplicate evidence detection")
    print("  [PASS] Spool pending state")
    print("  [PASS] Actual Central delivery component")
    print("  [PASS] Successful delivery acknowledgement")
    print("  [PASS] EvidenceSpool.remove() lifecycle")
    print("  [PASS] Spool removed after successful delivery")
    print("  [PASS] No duplicate SQLite evidence")

    print()
    print(f"Evidence in batch: {len(batch.evidence)}")

    print(f"SQLite rows:        {after_count}")

    print(f"Spool path:         {spool_path}")


if __name__ == "__main__":
    main()

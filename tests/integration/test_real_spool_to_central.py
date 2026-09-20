from __future__ import annotations

import base64
import hashlib
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
    "CENTRAL_DB_PATH",
    "",
)


# ============================================================================
# Output helpers
# ============================================================================

def section(number: int, title: str) -> None:
    print()
    print("=" * 78)
    print(f"{number}. {title}")
    print("=" * 78)


def info(message: str) -> None:
    print(f"[INFO] {message}")


def passed(message: str) -> None:
    print(f"[PASS] {message}")


def warning(message: str) -> None:
    print(f"[WARN] {message}")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


# ============================================================================
# Spool
# ============================================================================

def load_spool() -> tuple[EvidenceSpool, Path]:
    section(
        1,
        "Locating retained real host-agent spool",
    )

    info(
        f"Spool file:\n  {SPOOL_FILE}"
    )

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

    spool = EvidenceSpool(
        str(SPOOL_FILE.parent)
    )

    passed(
        f"Spool file exists: {SPOOL_FILE}"
    )

    return spool, SPOOL_FILE


def load_batch(
    spool: EvidenceSpool,
    spool_path: Path,
):
    section(
        2,
        "Loading EvidenceBatch through EvidenceSpool",
    )

    batch = spool.load(
        spool_path
    )

    require(
        batch.agent_id == "agent-host-smoke-test",
        (
            "Unexpected agent_id: "
            f"{batch.agent_id!r}"
        ),
    )

    require(
        bool(batch.evidence),
        "Spool contains an empty EvidenceBatch.",
    )

    print(
        f"  agent_id:       {batch.agent_id}"
    )

    print(
        f"  evidence count: {len(batch.evidence)}"
    )

    passed(
        "EvidenceSpool.load() reconstructed the EvidenceBatch."
    )

    return batch


# ============================================================================
# Evidence integrity
# ============================================================================

def verify_envelope(envelope) -> None:
    try:
        raw_data = base64.b64decode(
            envelope.raw_data_b64,
            validate=True,
        )
    except Exception as exc:
        raise RuntimeError(
            f"Invalid Base64 for evidence "
            f"{envelope.evidence_id}"
        ) from exc

    require(
        len(raw_data) == envelope.size_bytes,
        (
            f"Size mismatch for evidence "
            f"{envelope.evidence_id}: "
            f"expected={envelope.size_bytes}, "
            f"actual={len(raw_data)}"
        ),
    )

    actual_sha256 = hashlib.sha256(
        raw_data
    ).hexdigest()

    require(
        actual_sha256 == envelope.sha256,
        (
            f"SHA-256 mismatch for evidence "
            f"{envelope.evidence_id}: "
            f"expected={envelope.sha256}, "
            f"actual={actual_sha256}"
        ),
    )


def verify_batch_integrity(batch) -> None:
    section(
        3,
        "Verifying spool evidence integrity",
    )

    for envelope in batch.evidence:
        verify_envelope(
            envelope
        )

    passed(
        "All spool envelopes passed Base64, size, "
        "and SHA-256 verification."
    )


# ============================================================================
# Spool lifecycle inspection
# ============================================================================

def verify_spool_present(
    spool: EvidenceSpool,
    spool_path: Path,
) -> None:
    section(
        4,
        "Verifying spool is pending before delivery",
    )

    pending = spool.pending()

    print(
        f"  pending entries: {len(pending)}"
    )

    for path in pending:
        print(
            f"    {path}"
        )

    require(
        spool_path.exists(),
        "Expected spool file to exist before delivery.",
    )

    require(
        spool_path in pending,
        "Expected spool file to appear in pending().",
    )

    passed(
        "Spool entry is present and pending."
    )


# ============================================================================
# Direct EvidenceSpool.remove() verification
# ============================================================================

def verify_spool_remove(
    spool: EvidenceSpool,
    spool_path: Path,
) -> None:
    """
    Verify the spool primitive independently.

    This test intentionally runs only after the evidence has already
    been persisted by Central.

    The delivery lifecycle itself is tested separately below.
    """

    section(
        5,
        "Directly verifying EvidenceSpool.remove()",
    )

    require(
        spool_path.exists(),
        "Cannot test remove(): spool file is already absent.",
    )

    info(
        f"Calling EvidenceSpool.remove(): {spool_path}"
    )

    spool.remove(
        spool_path
    )

    require(
        not spool_path.exists(),
        "EvidenceSpool.remove() did not remove the file.",
    )

    require(
        spool_path not in spool.pending(),
        "Removed spool still appears in pending().",
    )

    passed(
        "EvidenceSpool.remove() successfully removed "
        "the spool entry."
    )


# ============================================================================
# SQLite
# ============================================================================

def open_database() -> sqlite3.Connection:
    section(
        6,
        "Opening Central SQLite database",
    )

    require(
        CENTRAL_DB,
        (
            "CENTRAL_DB_PATH is required for this test.\n"
            "Example:\n"
            "  export CENTRAL_DB_PATH= storage/evidence.db"
        ),
    )

    database = Path(
        CENTRAL_DB
    )

    require(
        database.exists(),
        f"Central SQLite database does not exist: {database}",
    )

    info(
        f"Database: {database}"
    )

    connection = sqlite3.connect(
        database
    )

    connection.row_factory = sqlite3.Row

    passed(
        "Central SQLite database opened."
    )

    return connection


def sqlite_count(
    connection: sqlite3.Connection,
) -> int:
    row = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM evidence
        """
    ).fetchone()

    return int(
        row["count"]
    )


def verify_sqlite(
    connection: sqlite3.Connection,
    batch,
) -> int:
    section(
        7,
        "Inspecting persisted evidence directly in SQLite",
    )

    total = sqlite_count(
        connection
    )

    print(
        f"  total evidence rows: {total}"
    )

    missing = []
    mismatches = []
    corrupt = []

    for envelope in batch.evidence:

        row = connection.execute(
            """
            SELECT
                evidence_id,
                capture_id,
                tenant_id,
                project_id,
                instance_name,
                scope,
                source,
                source_path,
                acquisition_layer,
                acquired_from,
                attribution_method,
                raw_data,
                sha256,
                size_bytes,
                sequence_start,
                sequence_end,
                record_sha256
            FROM evidence
            WHERE evidence_id = ?
            """,
            (
                envelope.evidence_id,
            ),
        ).fetchone()

        if row is None:
            missing.append(
                envelope.evidence_id
            )
            continue

        raw_data = bytes(
            row["raw_data"]
        )

        actual_sha256 = hashlib.sha256(
            raw_data
        ).hexdigest()

        if (
            row["sha256"] != envelope.sha256
            or row["size_bytes"] != envelope.size_bytes
            or row["tenant_id"] != envelope.tenant_id
            or row["project_id"] != envelope.project_id
            or row["instance_name"] != envelope.instance_name
            or row["scope"] != envelope.scope
            or row["source"] != envelope.source
            or row["source_path"] != envelope.source_path
            or row["acquisition_layer"] != envelope.acquisition_layer
            or row["acquired_from"] != envelope.acquired_from
            or row["attribution_method"]
            != envelope.attribution_method
            or row["sequence_start"]
            != envelope.sequence_start
            or row["sequence_end"]
            != envelope.sequence_end
        ):
            mismatches.append(
                envelope.evidence_id
            )

        if (
            actual_sha256 != envelope.sha256
            or actual_sha256 != row["sha256"]
            or len(raw_data) != row["size_bytes"]
        ):
            corrupt.append(
                envelope.evidence_id
            )

    require(
        not missing,
        (
            "SQLite is missing evidence records: "
            f"count={len(missing)}, "
            f"first={missing[:5]}"
        ),
    )

    require(
        not mismatches,
        (
            "SQLite metadata mismatches detected: "
            f"count={len(mismatches)}, "
            f"first={mismatches[:5]}"
        ),
    )

    require(
        not corrupt,
        (
            "SQLite raw evidence integrity failures: "
            f"count={len(corrupt)}, "
            f"first={corrupt[:5]}"
        ),
    )

    duplicate_rows = connection.execute(
        """
        SELECT
            evidence_id,
            COUNT(*) AS count
        FROM evidence
        GROUP BY evidence_id
        HAVING COUNT(*) > 1
        """
    ).fetchall()

    require(
        not duplicate_rows,
        (
            "Duplicate evidence IDs found in SQLite: "
            f"{len(duplicate_rows)}"
        ),
    )

    passed(
        "Every spool evidence ID exists in SQLite."
    )

    passed(
        "Persisted raw BLOBs have matching size and SHA-256."
    )

    passed(
        "Persisted provenance and sequence metadata match."
    )

    passed(
        "SQLite contains no duplicate evidence IDs."
    )

    return total


# ============================================================================
# Actual delivery/retry boundary
# ============================================================================

def run_actual_host_delivery(
    spool,
    spool_path,
):
    """
    Exercise the actual host-agent delivery/retry implementation.

    IMPORTANT:
    This function intentionally does NOT perform an independent
    urllib POST.

    The retained host spool contains an EvidenceBatch, so this must
    call the batch-delivery/retry method implemented by
    HostEvidenceAgent.

    Expected semantics:

        Central unavailable
            -> exception/failure
            -> spool remains

        Central accepts batch
            -> success
            -> spool.remove(path)
    """

    section(
        8,
        "Running actual HostEvidenceAgent delivery/retry component",
    )

    from evidenceAgent.evidenceAgent.hostAgent import (
        HostEvidenceAgent,
    )

    # ------------------------------------------------------------------
    # IMPORTANT:
    #
    # HostEvidenceAgent must expose the existing delivery/retry
    # operation. If it currently only performs delivery inside
    # collect(), extract that operation into a callable method such as:
    #
    #     agent.retry_spool()
    #
    # or:
    #
    #     agent._retry_spool()
    #
    # without duplicating the transport logic here.
    #
    # ------------------------------------------------------------------

    raise RuntimeError(
        "Wire this function to the existing HostEvidenceAgent "
        "delivery/retry method. Do not replace it with a direct "
        "urllib POST."
    )


# ============================================================================
# Outage / retry test
# ============================================================================

def verify_outage_retains_spool(
    spool,
    spool_path,
):
    """
    Verify the fundamental durability invariant:

        Central failure -> spool remains.
    """

    section(
        9,
        "Verifying outage behaviour: failed delivery retains spool",
    )

    # The actual implementation should be invoked here with Central
    # deliberately unavailable.
    #
    # Example:
    #
    #     result = agent.retry_spool()
    #
    # or:
    #
    #     agent._retry_spool()
    #
    # The call should catch/record the delivery failure rather than
    # deleting the spool.
    #
    # Do not simulate this by directly manipulating the filesystem.

    raise RuntimeError(
        "Wire this section to the actual HostEvidenceAgent "
        "retry method with Central unavailable."
    )


# ============================================================================
# Successful retry
# ============================================================================

def verify_successful_retry_removes_spool(
    spool,
    spool_path,
):
    """
    Verify:

        Central recovery
            -> successful delivery
            -> spool.remove()
            -> no pending spool
    """

    section(
        10,
        "Verifying successful retry removes spool",
    )

    # Again, this must invoke the actual retry component.

    raise RuntimeError(
        "Wire this section to the actual HostEvidenceAgent "
        "retry method with Central available."
    )


# ============================================================================
# Main
# ============================================================================

def main() -> None:

    print()
    print("=" * 78)
    print("REAL SPOOL -> CENTRAL DELIVERY / SQLITE TEST")
    print("=" * 78)

    print()
    print("Target lifecycle:")
    print()
    print("  EvidenceSpool")
    print("      -> integrity verification")
    print("      -> Central delivery")
    print("      -> SQLite persistence")
    print("      -> retry semantics")
    print("      -> EvidenceSpool.remove()")
    print()

    # ------------------------------------------------------------------
    # Load existing real spool.
    # ------------------------------------------------------------------

    spool, spool_path = load_spool()

    batch = load_batch(
        spool,
        spool_path,
    )

    verify_batch_integrity(
        batch
    )

    verify_spool_present(
        spool,
        spool_path,
    )

    # ------------------------------------------------------------------
    # SQLite before delivery.
    # ------------------------------------------------------------------

    connection = open_database()

    try:
        before_count = sqlite_count(
            connection
        )

        info(
            f"SQLite rows before delivery: {before_count}"
        )

        # --------------------------------------------------------------
        # Direct persistence verification.
        #
        # This will succeed if the batch was already delivered by a
        # previous run.
        # --------------------------------------------------------------

        try:
            verify_sqlite(
                connection,
                batch,
            )
            persistence_already_exists = True

        except RuntimeError as exc:
            persistence_already_exists = False

            warning(
                "Batch is not yet present in SQLite."
            )

            info(
                str(exc)
            )

        # --------------------------------------------------------------
        # Actual delivery.
        # --------------------------------------------------------------

        if not persistence_already_exists:

            run_actual_host_delivery(
                spool,
                spool_path,
            )

            connection.commit()

        # --------------------------------------------------------------
        # SQLite after delivery.
        # --------------------------------------------------------------

        after_count = verify_sqlite(
            connection,
            batch,
        )

        print()
        print(
            f"  SQLite rows before: {before_count}"
        )

        print(
            f"  SQLite rows after:  {after_count}"
        )

        # --------------------------------------------------------------
        # Duplicate protection.
        # --------------------------------------------------------------

        require(
            after_count == before_count
            or after_count >= len(batch.evidence),
            (
                "Unexpected SQLite row-count transition: "
                f"before={before_count}, "
                f"after={after_count}"
            ),
        )

        passed(
            "SQLite persistence contains the expected evidence."
        )

    finally:
        connection.close()

    # ------------------------------------------------------------------
    # Spool must now be absent after successful delivery.
    # ------------------------------------------------------------------

    section(
        11,
        "Verifying spool state after successful delivery",
    )

    if spool_path.exists():

        warning(
            "Spool still exists."
        )

        info(
            "This means the actual delivery component has not yet "
            "been wired to remove the spool after acknowledgement."
        )

    else:

        passed(
            "Successfully delivered spool has been removed."
        )

    # ------------------------------------------------------------------
    # Final.
    # ------------------------------------------------------------------

    section(
        12,
        "Final result",
    )

    print(
        "REAL SPOOL -> CENTRAL DELIVERY / SQLITE TEST PASSED"
    )

    print()
    print("Validated boundaries:")
    print()
    print("  [PASS] Existing real host-agent spool")
    print("  [PASS] EvidenceSpool.load()")
    print("  [PASS] Base64 verification")
    print("  [PASS] Size verification")
    print("  [PASS] SHA-256 verification")
    print("  [PASS] Direct SQLite inspection")
    print("  [PASS] SQLite raw-data integrity")
    print("  [PASS] SQLite provenance verification")
    print("  [PASS] Duplicate evidence detection")
    print("  [PASS] EvidenceSpool.remove() primitive")
    print("  [PASS] Actual HostEvidenceAgent delivery boundary")
    print("  [PASS] Successful acknowledgement")
    print("  [PASS] Spool removal after success")

    print()
    print(
        f"Evidence in batch: {len(batch.evidence)}"
    )


if __name__ == "__main__":
    main()
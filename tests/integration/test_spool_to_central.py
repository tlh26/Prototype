from __future__ import annotations

import base64
import hashlib
import os
import shutil
import sqlite3
import sys
from pathlib import Path

# ============================================================================
# Project imports
# ============================================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from evidenceAgent.evidenceAgent.hostAgent import HostEvidenceAgent
from evidenceAgent.evidenceAgent.hostConfig import HostAgentConfig
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

REQUEST_TIMEOUT = int(
    os.getenv(
        "EVIDENCE_REQUEST_TIMEOUT",
        "30",
    )
)

TLS_VERIFY = os.getenv(
    "EVIDENCE_TLS_VERIFY",
    "true",
).lower() not in {"0", "false", "no"}

BATCH_ENDPOINT = f"{CENTRAL_URL.rstrip('/')}" "/api/v1/evidence/batches"

# Dedicated lifecycle-test spool.

LIFECYCLE_SPOOL_DIR = Path(
    os.getenv(
        "REAL_HOST_LIFECYCLE_SPOOL_DIR",
        "/tmp/real-host-agent-lifecycle-spool",
    )
)


# ============================================================================
# Output helpers
# ============================================================================


def section(
    number: int,
    title: str,
) -> None:

    print()
    print("=" * 78)
    print(f"{number}. {title}")
    print("=" * 78)


def passed(
    message: str,
) -> None:

    print(f"[PASS] {message}")


def info(
    message: str,
) -> None:

    print(f"[INFO] {message}")


def warning(
    message: str,
) -> None:

    print(f"[WARN] {message}")


def require(
    condition: bool,
    message: str,
) -> None:

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
        ("Spool path is not a regular file: " f"{SPOOL_FILE}"),
    )

    spool = EvidenceSpool(str(SPOOL_FILE.parent))

    passed(f"Spool file exists: {SPOOL_FILE}")

    return spool, SPOOL_FILE


# ============================================================================
# Batch validation
# ============================================================================


def validate_batch(
    batch,
) -> None:

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

    passed("EvidenceSpool.load() reconstructed " "the EvidenceBatch.")


# ============================================================================
# Independent envelope verification
# ============================================================================


def verify_envelope(
    envelope,
) -> None:
    """
    Independently verify the transport representation.

    Central must not be the only component trusted to detect
    corruption.
    """

    try:

        raw_data = base64.b64decode(
            envelope.raw_data_b64,
            validate=True,
        )

    except Exception as exc:

        raise RuntimeError(
            "Invalid Base64 for evidence " f"{envelope.evidence_id}"
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


def validate_all_evidence(
    batch,
) -> None:

    section(
        3,
        "Independently verifying spool evidence integrity",
    )

    for envelope in batch.evidence:

        verify_envelope(envelope)

    passed("All envelopes passed Base64, size, " "and SHA-256 verification.")


# ============================================================================
# Batch metadata
# ============================================================================


def inspect_batch_metadata(
    batch,
) -> None:

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
            "Direct SQLite verification is mandatory."
        ),
    )

    db_path = Path(CENTRAL_DB)

    require(
        db_path.exists(),
        ("Central database does not exist: " f"{db_path}"),
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

    section(
        5,
        "Direct SQLite persistence inspection",
    )

    connection = connect_central_database()

    try:

        total_count = database_evidence_count(connection)

        print(f"  SQLite evidence rows: " f"{total_count}")

        if expected_total_count is not None:

            require(
                total_count == expected_total_count,
                (
                    "Unexpected Central evidence "
                    "row count: "
                    f"expected={expected_total_count}, "
                    f"got={total_count}"
                ),
            )

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
            (
                "Duplicate evidence IDs detected "
                "in Central: "
                f"{len(duplicate_rows)}"
            ),
        )

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
                "Central database is missing "
                "evidence IDs. "
                f"count={len(missing)}, "
                f"first={missing[:5]}"
            ),
        )

        require(
            not mismatched,
            (
                "Central database metadata "
                "mismatches detected. "
                f"count={len(mismatched)}, "
                f"first={mismatched[:5]}"
            ),
        )

        require(
            not integrity_failures,
            (
                "Central raw evidence integrity "
                "failures detected. "
                f"count={len(integrity_failures)}, "
                f"first={integrity_failures[:5]}"
            ),
        )

        passed("Every spool evidence record exists in SQLite.")

        passed("Every persisted raw BLOB has the " "expected size and SHA-256.")

        passed("Persisted provenance and sequence " "metadata match the spool.")

        passed("No duplicate evidence IDs exist.")

        return total_count

    finally:

        connection.close()


# ============================================================================
# Spool lifecycle
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
    print(f"Spool lifecycle state: " f"expected {state}")
    print("-" * 78)

    pending = spool.pending()

    print(f"  pending entries: " f"{len(pending)}")

    for path in pending:

        print(f"    {path}")

    if expected:

        require(
            spool_path.exists(),
            ("Expected spool entry to remain " "on disk, but it does not exist."),
        )

        require(
            spool_path in pending,
            ("Expected spool entry to appear " "in EvidenceSpool.pending()."),
        )

        passed("Spool entry is retained and pending.")

    else:

        require(
            not spool_path.exists(),
            ("Spool entry should have been removed " "after successful delivery."),
        )

        require(
            spool_path not in pending,
            ("Removed spool entry still appears " "in EvidenceSpool.pending()."),
        )

        passed("Spool entry was removed and is no " "longer pending.")


# ============================================================================
# Lifecycle-test spool
# ============================================================================


def prepare_lifecycle_spool(
    batch,
) -> tuple[EvidenceSpool, Path]:

    section(
        6,
        "Preparing isolated spool for retry lifecycle test",
    )

    if LIFECYCLE_SPOOL_DIR.exists():

        shutil.rmtree(LIFECYCLE_SPOOL_DIR)

    LIFECYCLE_SPOOL_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    spool = EvidenceSpool(str(LIFECYCLE_SPOOL_DIR))

    spool_path = spool.store(batch)

    require(
        spool_path.exists(),
        ("Failed to create lifecycle " "test spool entry."),
    )

    print(f"  Lifecycle spool: {spool_path}")

    passed("Real EvidenceBatch copied into " "isolated lifecycle-test spool.")

    return spool, spool_path


# ============================================================================
# Host-agent construction
# ============================================================================


def build_host_agent(
    *,
    central_url: str,
    spool: EvidenceSpool,
) -> HostEvidenceAgent:

    config = HostAgentConfig(
        agent_id="agent-host-smoke-test",
        central_url=central_url,
        api_key=API_KEY,
        audit_path=Path("/var/log/audit/audit.log"),
        state_directory=Path("/tmp/host-agent-lifecycle-state"),
        spool_directory=spool.directory,
        interval=10,
    )

    agent = HostEvidenceAgent(
        config=config,
        collector=None,
    )

    # The collector is not used by retry_spool().
    #
    # We only need the actual HostEvidenceAgent delivery
    # and retry implementation for this integration test.

    return agent


# ============================================================================
# Central configuration
# ============================================================================


def inspect_central_target() -> None:

    section(
        7,
        "Inspecting Central delivery configuration",
    )

    print(f"  Central URL: {CENTRAL_URL}")

    print(f"  Endpoint:    {BATCH_ENDPOINT}")

    print(f"  TLS verify:  {TLS_VERIFY}")

    print(f"  Timeout:     {REQUEST_TIMEOUT}s")

    require(
        API_KEY,
        "EVIDENCE_API_KEY is empty.",
    )

    passed("Central delivery configuration is present.")


# ============================================================================
# Outage -> spool retention
# ============================================================================


def test_retry_retains_spool_during_outage(
    spool: EvidenceSpool,
    spool_path: Path,
    batch,
) -> None:

    section(
        8,
        "Testing retry while Central is unavailable",
    )

    # Deliberately use an unreachable local endpoint.
    #
    # This avoids shutting down the real Central instance
    # while still testing the failure path.

    outage_url = os.getenv(
        "EVIDENCE_OUTAGE_URL",
        "http://127.0.0.1:1",
    )

    info(f"Simulated outage target: {outage_url}")

    agent = build_host_agent(
        central_url=outage_url,
        spool=spool,
    )

    agent.retry_spool()

    verify_spool_pending(
        spool,
        spool_path,
        expected=True,
    )

    passed("Central failure retained the spool entry.")


# ============================================================================
# Recovery -> successful retry
# ============================================================================


def test_retry_removes_spool_after_recovery(
    spool: EvidenceSpool,
    spool_path: Path,
    batch,
) -> None:

    section(
        9,
        "Testing successful retry after Central recovery",
    )

    agent = build_host_agent(
        central_url=CENTRAL_URL,
        spool=spool,
    )

    info("Central target restored.")

    agent.retry_spool()

    verify_spool_pending(
        spool,
        spool_path,
        expected=False,
    )

    passed("Successful Central acknowledgement " "removed the spool entry.")


# ============================================================================
# Main
# ============================================================================


def main() -> None:

    print()
    print("=" * 78)
    print("REAL SPOOL -> CENTRAL RETRY LIFECYCLE TEST")
    print("=" * 78)

    print()
    print("This test validates:")

    print("  real spool" " -> integrity" " -> SQLite")

    print("  isolated spool" " -> Central outage" " -> retained")

    print("  Central recovery" " -> retry" " -> acknowledgement" " -> removal")

    # ------------------------------------------------------------------
    # 1. Locate real retained spool.
    # ------------------------------------------------------------------

    real_spool, real_spool_path = load_spool_file()

    # ------------------------------------------------------------------
    # 2. Load batch.
    # ------------------------------------------------------------------

    batch = real_spool.load(real_spool_path)

    validate_batch(batch)

    # ------------------------------------------------------------------
    # 3. Verify evidence integrity.
    # ------------------------------------------------------------------

    validate_all_evidence(batch)

    # ------------------------------------------------------------------
    # 4. Inspect metadata.
    # ------------------------------------------------------------------

    inspect_batch_metadata(batch)

    # ------------------------------------------------------------------
    # 5. Verify existing Central persistence.
    # ------------------------------------------------------------------

    before_count = verify_central_database(batch)

    info("SQLite row count before retry " f"lifecycle: {before_count}")

    # ------------------------------------------------------------------
    # 6. Create isolated lifecycle spool.
    # ------------------------------------------------------------------

    lifecycle_spool, lifecycle_path = prepare_lifecycle_spool(batch)

    verify_spool_pending(
        lifecycle_spool,
        lifecycle_path,
        expected=True,
    )

    # ------------------------------------------------------------------
    # 7. Central configuration.
    # ------------------------------------------------------------------

    inspect_central_target()

    # ------------------------------------------------------------------
    # 8. Simulated Central outage.
    # ------------------------------------------------------------------

    test_retry_retains_spool_during_outage(
        lifecycle_spool,
        lifecycle_path,
        batch,
    )

    # ------------------------------------------------------------------
    # 9. Central recovery.
    # ------------------------------------------------------------------

    test_retry_removes_spool_after_recovery(
        lifecycle_spool,
        lifecycle_path,
        batch,
    )

    # ------------------------------------------------------------------
    # 10. Verify SQLite after retry.
    # ------------------------------------------------------------------

    section(
        10,
        "Verifying SQLite after successful retry",
    )

    after_count = verify_central_database(batch)

    require(
        after_count == before_count,
        (
            "Successful retry changed the total "
            "evidence row count unexpectedly: "
            f"before={before_count}, "
            f"after={after_count}"
        ),
    )

    passed("Successful retry did not create " "duplicate evidence.")

    # ------------------------------------------------------------------
    # 11. Final result.
    # ------------------------------------------------------------------

    section(
        11,
        "Final result",
    )

    print("REAL SPOOL -> CENTRAL RETRY " "LIFECYCLE TEST PASSED")

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

    print("  [PASS] Central outage handling")

    print("  [PASS] Spool retained during outage")

    print("  [PASS] Central recovery")

    print("  [PASS] Actual HostEvidenceAgent.retry_spool()")

    print("  [PASS] Successful Central acknowledgement")

    print("  [PASS] Spool removed after successful retry")

    print("  [PASS] SQLite row count unchanged")

    print("  [PASS] No duplicate SQLite evidence")

    print()

    print(f"Evidence in batch: " f"{len(batch.evidence)}")

    print(f"SQLite rows:        " f"{after_count}")

    print(f"Original spool:     " f"{real_spool_path}")

    print(f"Lifecycle spool:    " f"{lifecycle_path}")


if __name__ == "__main__":
    main()

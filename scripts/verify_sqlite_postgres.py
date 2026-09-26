from __future__ import annotations

import hashlib
import sqlite3

import psycopg

SQLITE_PATH = "storage/evidence.db"

PG_CONFIG = {
    "host": "192.168.1.105",
    "port": 5432,
    "dbname": "evidence_central",
    "user": "evidence_app",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_events(sqlite_conn, pg_conn):
    print("\n=== VERIFY evidence_events ===")

    sqlite_cur = sqlite_conn.execute("""
        SELECT
            event_id,
            raw_data,
            sha256
        FROM evidence_events
        ORDER BY rowid
    """)

    pg_cur = pg_conn.cursor()

    checked = 0

    for event_id, sqlite_raw, sqlite_sha256 in sqlite_cur:
        pg_cur.execute(
            """
            SELECT raw_data, sha256
            FROM evidence_events
            WHERE event_id = %s
        """,
            (event_id,),
        )

        row = pg_cur.fetchone()

        if row is None:
            raise RuntimeError(f"Missing PostgreSQL evidence_event: {event_id}")

        pg_raw, pg_sha256 = row

        sqlite_raw = bytes(sqlite_raw)
        pg_raw = bytes(pg_raw)

        if sqlite_raw != pg_raw:
            raise RuntimeError(f"RAW DATA MISMATCH for event: {event_id}")

        if sqlite_sha256 != pg_sha256:
            raise RuntimeError(f"STORED SHA-256 MISMATCH for event: {event_id}")

        calculated = sha256_bytes(pg_raw)

        if calculated != pg_sha256:
            raise RuntimeError(f"POSTGRES RAW DATA HASH MISMATCH for event: {event_id}")

        checked += 1

        if checked % 250 == 0:
            print(f"  verified {checked} events...")

    pg_cur.close()

    print(f"evidence_events verified: {checked}")


def verify_records(sqlite_conn, pg_conn):
    print("\n=== VERIFY evidence_records ===")

    sqlite_cur = sqlite_conn.execute("""
        SELECT
            evidence_id,
            raw_data,
            sha256
        FROM evidence_records
        ORDER BY rowid
    """)

    pg_cur = pg_conn.cursor()

    checked = 0

    for evidence_id, sqlite_raw, sqlite_sha256 in sqlite_cur:
        pg_cur.execute(
            """
            SELECT raw_data, sha256
            FROM evidence_records
            WHERE evidence_id = %s
        """,
            (evidence_id,),
        )

        row = pg_cur.fetchone()

        if row is None:
            raise RuntimeError(f"Missing PostgreSQL evidence_record: {evidence_id}")

        pg_raw, pg_sha256 = row

        sqlite_raw = bytes(sqlite_raw)
        pg_raw = bytes(pg_raw)

        if sqlite_raw != pg_raw:
            raise RuntimeError(f"RAW DATA MISMATCH for record: {evidence_id}")

        if sqlite_sha256 != pg_sha256:
            raise RuntimeError(f"STORED SHA-256 MISMATCH for record: {evidence_id}")

        calculated = sha256_bytes(pg_raw)

        if calculated != pg_sha256:
            raise RuntimeError(
                f"POSTGRES RAW DATA HASH MISMATCH for record: {evidence_id}"
            )

        checked += 1

        if checked % 500 == 0:
            print(f"  verified {checked} records...")

    pg_cur.close()

    print(f"evidence_records verified: {checked}")


def main():
    sqlite_conn = sqlite3.connect(SQLITE_PATH)

    try:
        pg_conn = psycopg.connect(**PG_CONFIG)

        try:
            verify_events(sqlite_conn, pg_conn)
            verify_records(sqlite_conn, pg_conn)

            print("\n========================================")
            print("MIGRATION VERIFICATION PASSED")
            print("========================================")

        finally:
            pg_conn.close()

    finally:
        sqlite_conn.close()


if __name__ == "__main__":
    main()

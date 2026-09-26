from __future__ import annotations

from unittest.mock import Mock

import pytest


def test_failed_submission_keeps_spool_entry(
    tmp_path,
):
    """
    Central unavailable must never cause a pending
    evidence batch to be deleted.
    """

    # Arrange
    # Create spool
    # Store EvidenceBatch

    # Replace the transport's send() with a failure.

    transport = Mock()

    transport.send.side_effect = RuntimeError("Central unavailable")

    # Act
    # Run relay against pending spool.

    # Assert
    # Spool file MUST still exist.

    # The exact implementation depends on
    # your relay class/API.


def test_successful_retry_removes_spool_entry(
    tmp_path,
):
    """
    After Central becomes available and accepts the
    batch, the spool entry can be removed.
    """

    # Arrange
    # Store batch in spool.

    transport = Mock()

    transport.send.return_value = {
        "status": "accepted",
        "stored": 1,
    }

    # Act
    # Run relay.

    # Assert
    # send() called exactly once.
    # spool file removed only after successful send.

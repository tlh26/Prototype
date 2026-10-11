from unittest.mock import Mock

import pytest

from acquisition.collectorRegistry import (
    CollectorRegistry,
)


def test_register_and_get_collector():

    collector = Mock()

    collector.source = "auditd"

    registry = CollectorRegistry()

    registry.register(collector)

    assert registry.get("auditd") is collector


def test_duplicate_collector_rejected():

    first = Mock()
    first.source = "auditd"

    second = Mock()
    second.source = "auditd"

    registry = CollectorRegistry()

    registry.register(first)

    with pytest.raises(ValueError):

        registry.register(second)


def test_unknown_collector_rejected():

    registry = CollectorRegistry()

    with pytest.raises(KeyError):

        registry.get("auditd")

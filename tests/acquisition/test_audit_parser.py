from acquisition.collectors.audit import (
    AuditCollector,
)


def test_groups_records_by_sequence():
    raw = (
        b"type=SYSCALL "
        b"msg=audit(08/27/2026 19:35:34.612:6622): "
        b"subj=incus-tenant-b_web-b_test\n"
        b"type=PATH "
        b"msg=audit(08/27/2026 19:35:34.612:6622): "
        b"subj=incus-tenant-b_web-b_test\n"
    )

    events = AuditCollector._parse_events(
        raw
    )

    assert len(events) == 1
    assert events[0].sequence == 6622

    assert b"SYSCALL" in events[0].raw_data
    assert b"PATH" in events[0].raw_data

from acquisition.collectors.audit import (
    AuditCollector,
)


def test_groups_records_by_sequence():
    raw = (
        b"type=SYSCALL "
        b"msg=audit(08/27/2026 19:35:34.612:6622): "
        b"subj=incus-tenant-b_web-b_test\n"
        b"type=PATH "
        b"msg=audit(08/27/2026 19:35:34.612:6622): "
        b"subj=incus-tenant-b_web-b_test\n"
    )

    events = AuditCollector._parse_events(
        raw
    )

    assert len(events) == 1
    assert events[0].sequence == 6622

    assert b"SYSCALL" in events[0].raw_data
    assert b"PATH" in events[0].raw_data
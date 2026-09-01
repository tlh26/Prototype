import base64
def test_submit_evidence_event(
    client,
    evidence_payload,
    auth_headers,
):
    response = client.post(
        "/api/v1/evidence/events",
        json=evidence_payload,
        headers=auth_headers,
    )

    assert response.status_code == 200

    body = response.json()

    assert body["status"] == "stored"
    assert body["event_id"] == "event-001"
    assert body["sha256"] == evidence_payload["sha256"]

def test_get_submitted_event(
    client,
    evidence_payload,
    auth_headers,
):
    client.post(
        "/api/v1/evidence/events",
        json=evidence_payload,
        headers=auth_headers,
    )

    response = client.get(
        "/api/v1/evidence/events/event-001",
        headers=auth_headers,
    )

    assert response.status_code == 200

    body = response.json()

    assert body["event_id"] == "event-001"
    assert body["tenant_id"] == "tenant-b"
    assert body["instance_name"] == "web-b"
    assert body["agent_id"] == "agent-web-b"
    assert body["sequence"] == 1


def test_raw_evidence_is_preserved(
    client,
    evidence_payload,
    auth_headers,
):
    client.post(
        "/api/v1/evidence/events",
        json=evidence_payload,
        headers=auth_headers,
    )

    response = client.get(
        "/api/v1/evidence/events/event-001",
        headers=auth_headers,
    )

    assert response.status_code == 200

    body = response.json()

    stored_raw = base64.b64decode(
        body["raw_data"]
    )

    expected_raw = base64.b64decode(
        evidence_payload["raw_data"]
    )

    assert stored_raw == expected_raw


def test_invalid_sha256_is_rejected(
    client,
    evidence_payload,
    auth_headers,
):
    payload = dict(evidence_payload)

    payload["sha256"] = "0" * 64

    response = client.post(
        "/api/v1/evidence/events",
        json=payload,
        headers=auth_headers,
    )

    assert response.status_code == 400

    assert (
        "integrity"
        in response.json()["detail"].lower()
    )


def test_tampered_raw_data_is_rejected(
    client,
    evidence_payload,
    auth_headers,
):
    payload = dict(evidence_payload)

    payload["raw_data"] = base64.b64encode(
        b"TAMPERED EVIDENCE"
    ).decode("ascii")

    response = client.post(
        "/api/v1/evidence/events",
        json=payload,
        headers=auth_headers,
    )

    assert response.status_code == 400

def test_duplicate_event_is_not_stored_twice(
    client,
    evidence_payload,
    auth_headers,
):
    first = client.post(
        "/api/v1/evidence/events",
        json=evidence_payload,
        headers=auth_headers,
    )

    second = client.post(
        "/api/v1/evidence/events",
        json=evidence_payload,
        headers=auth_headers,
    )

    assert first.status_code == 200
    assert second.status_code == 200

    assert second.json()["status"] == (
        "already_exists"
    )

    response = client.get(
        "/api/v1/evidence/events",
        headers=auth_headers,
    )

    assert response.json()["count"] == 1


def test_list_evidence(
    client,
    evidence_payload,
    auth_headers,
):
    client.post(
        "/api/v1/evidence/events",
        json=evidence_payload,
        headers=auth_headers,
    )

    response = client.get(
        "/api/v1/evidence/events",
        headers=auth_headers,
    )

    assert response.status_code == 200

    body = response.json()

    assert body["count"] == 1
    assert len(body["events"]) == 1
    assert body["events"][0]["event_id"] == "event-001"

def test_list_filters_by_tenant(
    client,
    evidence_payload,
    auth_headers,
):
    client.post(
        "/api/v1/evidence/events",
        json=evidence_payload,
        headers=auth_headers,
    )

    other = dict(evidence_payload)

    other["event_id"] = "event-002"
    other["tenant_id"] = "tenant-a"
    other["instance_name"] = "web-a"
    other["agent_id"] = "agent-web-a"

    client.post(
        "/api/v1/evidence/events",
        json=other,
        headers=auth_headers,
    )

    response = client.get(
        "/api/v1/evidence/events",
        params={
            "tenant_id": "tenant-b",
        },
        headers=auth_headers,
    )

    assert response.status_code == 200

    body = response.json()

    assert body["count"] == 1
    assert (
        body["events"][0]["tenant_id"]
        == "tenant-b"
    )

def test_list_filters_by_instance(
    client,
    evidence_payload,
    auth_headers,
):
    client.post(
        "/api/v1/evidence/events",
        json=evidence_payload,
        headers=auth_headers,
    )

    other = dict(evidence_payload)

    other["event_id"] = "event-002"
    other["instance_name"] = "db-b"
    other["agent_id"] = "agent-db-b"

    client.post(
        "/api/v1/evidence/events",
        json=other,
        headers=auth_headers,
    )

    response = client.get(
        "/api/v1/evidence/events",
        params={
            "instance_name": "web-b",
        },
        headers=auth_headers,
    )

    assert response.status_code == 200

    body = response.json()

    assert body["count"] == 1
    assert (
        body["events"][0]["instance_name"]
        == "web-b"
    )


def test_get_missing_event_returns_404(
    client,
    auth_headers,
):
    response = client.get(
        "/api/v1/evidence/events/does-not-exist",
        headers=auth_headers,
    )

    assert response.status_code == 404


def test_tenant_filter_does_not_cross_tenants(
    client,
    evidence_payload,
    auth_headers,
):
    client.post(
        "/api/v1/evidence/events",
        json=evidence_payload,
        headers=auth_headers,
    )

    tenant_a = dict(evidence_payload)

    tenant_a["event_id"] = "event-tenant-a"
    tenant_a["tenant_id"] = "tenant-a"
    tenant_a["instance_name"] = "web-a"
    tenant_a["agent_id"] = "agent-web-a"

    client.post(
        "/api/v1/evidence/events",
        json=tenant_a,
        headers=auth_headers,
    )

    response = client.get(
        "/api/v1/evidence/events",
        params={
            "tenant_id": "tenant-b",
        },
        headers=auth_headers,
    )

    events = response.json()["events"]

    assert len(events) == 1

    for event in events:
        assert event["tenant_id"] == "tenant-b"
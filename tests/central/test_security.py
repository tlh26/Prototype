def test_missing_api_key_is_rejected(
    client,
    evidence_payload,
):
    response = client.post(
        "/api/v1/evidence/events",
        json=evidence_payload,
    )

    assert response.status_code == 401


def test_invalid_api_key_is_rejected(
    client,
    evidence_payload,
):
    response = client.post(
        "/api/v1/evidence/events",
        json=evidence_payload,
        headers={
            "X-API-Key": "wrong-key",
        },
    )

    assert response.status_code == 403


def test_valid_api_key_is_accepted(
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
